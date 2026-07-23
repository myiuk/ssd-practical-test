const security = require("eslint-plugin-security");

module.exports = [
  security.configs.recommended,
  {
    files: ["app/static/js/**/*.js"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "script",
      globals: { document: "readonly", alert: "readonly" },
    },
  },
];
