import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const packageRoot = resolve(import.meta.dir, '..');

/*** Validate a manifest dependency before placing it in the isolated consumer manifest. */
function readDependency(
  manifest: unknown,
  section: 'dependencies' | 'devDependencies',
  name: string,
): string {
  if (typeof manifest !== 'object' || manifest === null || !(section in manifest)) {
    throw new Error(`Package manifest has no ${section}.`);
  }
  const dependencies = manifest[section];
  if (typeof dependencies !== 'object' || dependencies === null || !(name in dependencies)) {
    throw new Error(`Package manifest does not declare ${name}.`);
  }
  const dependency = dependencies[name];
  if (typeof dependency !== 'string') throw new Error(`Package dependency ${name} is invalid.`);
  return dependency;
}

/*** Execute one bounded package-consumer command and preserve its diagnostic output. */
async function runAsync(command: readonly string[], cwd: string): Promise<void> {
  const process = Bun.spawn({ cmd: [...command], cwd, stderr: 'inherit', stdout: 'inherit' });
  if ((await process.exited) !== 0)
    throw new Error(`Packed consumer command failed: ${command[1]}.`);
}

/*** Verify the built tarball from an isolated consumer using only published public entrypoints. */
async function testPackedConsumerAsync(): Promise<void> {
  const consumerRoot = await mkdtemp(join(tmpdir(), 'auth-cognito-packed-consumer-'));
  try {
    const packageManifest = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
    const awsSdkVersion = readDependency(
      packageManifest,
      'dependencies',
      '@aws-sdk/client-cognito-identity-provider',
    );
    const typescriptVersion = readDependency(packageManifest, 'devDependencies', 'typescript');
    const packedDirectory = join(consumerRoot, 'packed');
    await mkdir(packedDirectory);
    await runAsync(['bun', 'run', 'build'], packageRoot);
    await runAsync(['bun', 'pm', 'pack', '--destination', packedDirectory], packageRoot);
    const tarballs = (await readdir(packedDirectory)).filter((entry) => entry.endsWith('.tgz'));
    if (tarballs.length !== 1) throw new Error('Expected one packed auth-cognito tarball.');
    const tarball = join(packedDirectory, tarballs[0]);
    await writeFile(
      join(consumerRoot, 'package.json'),
      JSON.stringify({
        name: 'auth-cognito-packed-consumer',
        private: true,
        type: 'module',
        dependencies: {
          '@ankhorage/auth-cognito': `file:${tarball}`,
          '@aws-sdk/client-cognito-identity-provider': awsSdkVersion,
        },
        devDependencies: { typescript: typescriptVersion },
      }),
    );
    await writeFile(
      join(consumerRoot, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          module: 'ESNext',
          moduleResolution: 'bundler',
          noEmit: true,
          skipLibCheck: true,
          strict: true,
          target: 'ES2022',
        },
      }),
    );
    await writeFile(join(consumerRoot, 'index.ts'), consumerSource);
    await runAsync(['bun', 'install'], consumerRoot);
    await runAsync(['bunx', 'tsc'], consumerRoot);
    await runAsync(['bun', 'run', 'index.ts'], consumerRoot);
  } finally {
    await rm(consumerRoot, { force: true, recursive: true });
  }
}

const consumerSource = `
import { createCognitoAuthAdapter } from '@ankhorage/auth-cognito';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({
  region: 'eu-central-1',
  credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  requestHandler: {
    handle: () =>
      Promise.resolve({
        response: {
          statusCode: 200,
          headers: { 'content-type': 'application/x-amz-json-1.1' },
          body: new TextEncoder().encode(JSON.stringify({
            AuthenticationResult: {
              AccessToken: 'signed-access-token',
              ExpiresIn: 3600,
              RefreshToken: 'refresh-token',
            },
          })),
        },
      }),
  },
});
let session: null | {
  accessToken: string;
  expiresAt?: number;
  refreshToken?: string;
  tokenType?: string;
  user: { id: string };
} = null;
const adapter = createCognitoAuthAdapter({
  public: {
    region: 'eu-central-1',
    userPoolId: 'eu-central-1_example',
    clientId: 'public-client',
    hostedDomain: 'https://login.example.test',
    redirectUris: ['https://consumer.example.test/callback'],
  },
  client,
  sessions: {
    read: () => Promise.resolve(session),
    write: (nextSession) => { session = nextSession; return Promise.resolve(); },
    clear: () => { session = null; return Promise.resolve(); },
  },
  authorizationAttempts: {
    create: () => Promise.resolve(),
    consume: () => Promise.resolve(null),
  },
  verifyJwt: () => Promise.resolve({ sub: 'consumer-subject' }),
});
const successful = await adapter.signIn({
  identifier: { kind: 'email', value: 'consumer@example.test' },
  password: 'secure-password',
});
if (!successful.ok || successful.data?.user.id !== 'consumer-subject') {
  throw new Error('Expected a verified Cognito session from the packed package.');
}
const failed = await adapter.signIn({
  identifier: { kind: 'email', value: 'consumer@example.test' },
});
if (failed.ok || failed.error.code !== 'password_required') {
  throw new Error('Expected missing-password authentication to fail from the packed package.');
}
`;

await testPackedConsumerAsync();
