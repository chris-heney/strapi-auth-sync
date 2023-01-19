module.exports = [
  {
    method: "GET",
    path: "/",
    handler: "myController.index",
    config: {
      policies: [],
      auth: false,
    },
  },
  {
    method: "POST",
    path: "/callback",
    handler: "myController.login",
    config: {
      policies: [],
      auth: false,
    },
  },
  {
    method: "POST",
    path: "/register",
    handler: "myController.register",
    config: {
      policies: [],
      auth: false,
    },
  },
  {
    method: "POST",
    path: "/forgot-password",
    handler: "myController.forgotPassword",
    config: {
      policies: [],
      auth: false,
    },
  },
  {
    method: "PUT",
    path: "/reset-password",
    handler: "myController.resetPassword",
    config: {
      policies: [],
      auth: false,
    },
  },
  {
    method: "POST",
    path: "/change-password",
    handler: "myController.changePassword",
    config: {
      policies: [],
      auth: false,
    },
  },
];
