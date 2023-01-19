module.exports = ({ env }) => ({
  // ...
  "auth-provider": {
    enabled: true,
    resolve: "./src/plugins/auth-provider",
  },
  email: {
    config: {
      provider: "sendgrid",
      providerOptions: {
        apiKey: env("SENDGRID_API_KEY"),
      },
      settings: {
        defaultFrom: env("FROM_EMAIL"),
        defaultReplyTo: env("FROM_EMAIL"),
      },
    },
  },
  // ...
});
