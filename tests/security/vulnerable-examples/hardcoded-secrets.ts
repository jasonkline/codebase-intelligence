// Vulnerable code examples for testing hardcoded secrets detection

// VULNERABLE: Hardcoded API keys
export const config = {
  apiKey: 'sk-1234567890abcdefghijklmnopqrstuvwxyz', // VULNERABLE
  secretKey: 'abc123def456ghi789jkl012mno345pqr678', // VULNERABLE
  databasePassword: 'super_secret_password_123', // VULNERABLE
};

// VULNERABLE: Hardcoded tokens
export class AuthService {
  private readonly jwtSecret = 'my-super-secret-jwt-key-2023'; // VULNERABLE
  private readonly refreshToken = 'refresh_token_abc123def456'; // VULNERABLE
  
  authenticate() {
    const token = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // VULNERABLE
    return token;
  }
}

// VULNERABLE: Database credentials
export function connectToDatabase() {
  const connectionString = 'postgresql://user:password123@localhost:5432/mydb'; // VULNERABLE
  return connectionString;
}

// VULNERABLE: Third-party service keys
export const integrations = {
  stripe: {
    publishableKey: 'pk_test_1234567890abcdefghijklmnopqrstuvwxyz', // VULNERABLE
    secretKey: 'sk_test_abcdefghijklmnopqrstuvwxyz1234567890', // VULNERABLE
  },
  github: {
    clientId: 'ghp_abcdefghijklmnopqrstuvwxyz123456789', // VULNERABLE
    clientSecret: 'github_secret_key_abcdefghijklmnop', // VULNERABLE
  },
  openai: {
    apiKey: 'sk-abcd1234efgh5678ijkl9012mnop3456qrst7890', // VULNERABLE
  },
};

// VULNERABLE: Encryption keys
export const crypto = {
  encryptionKey: 'encryption_key_32_bytes_long_123', // VULNERABLE
  salt: 'salt_value_for_hashing_passwords', // VULNERABLE
  iv: 'initialization_vector_16_bytes', // VULNERABLE
};

// VULNERABLE: OAuth secrets
export const oauth = {
  googleClientSecret: 'GOCSPX-abcdefghijklmnopqrstuvwxyz123456', // VULNERABLE
  facebookAppSecret: 'facebook_app_secret_1234567890abcdef', // VULNERABLE
  twitterConsumerSecret: 'twitter_consumer_secret_abcdefgh', // VULNERABLE
};

// VULNERABLE: Webhook secrets
export const webhooks = {
  stripeWebhookSecret: 'whsec_abcdefghijklmnopqrstuvwxyz123456', // VULNERABLE
  githubWebhookSecret: 'github_webhook_secret_123456789', // VULNERABLE
};

// VULNERABLE: Cloud service keys
export const aws = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE', // VULNERABLE
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // VULNERABLE
  region: 'us-east-1',
};

// VULNERABLE: Mixed with legitimate config
export const appConfig = {
  appName: 'MyApp',
  version: '1.0.0',
  apiEndpoint: 'https://api.example.com',
  secretKey: 'production_secret_key_dont_commit', // VULNERABLE
  debug: false,
  port: 3000,
};

// SECURE: Using environment variables
export const secureConfig = {
  apiKey: process.env.API_KEY,
  secretKey: process.env.SECRET_KEY,
  databaseUrl: process.env.DATABASE_URL,
};

// SECURE: Using secrets management
export async function getSecrets() {
  const secrets = await secretManager.getSecret('app-secrets');
  return {
    apiKey: secrets.API_KEY,
    databasePassword: secrets.DB_PASSWORD,
  };
}

// NOTE: These should NOT be flagged as they're obviously test values
export const testConfig = {
  testApiKey: 'test_key',
  exampleSecret: 'example',
  placeholderToken: 'placeholder',
  dummyPassword: 'dummy',
};