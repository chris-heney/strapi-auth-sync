"use strict";
require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { validateEmail } = require("../utils/validateEmail");
const { sendEmail } = require("../utils/sendEmail");

module.exports = ({ strapi }) => ({
  index(ctx) {
    ctx.body = strapi
      .plugin("auth-provider")
      .service("myService")
      .getWelcomeMessage();
  },
  async login(ctx) {
    // console.log(ctx.request.body);
    const { identifier, password } = ctx.request.body;
    if (!identifier || !password) {
      ctx.throw(400, "Please email and password");
    }
    if (!validateEmail(identifier)) {
      ctx.throw(400, "Please provide valid email address");
    }
    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: { email: identifier },
      });
    // console.log("jwt secret", process.env.JWT_SECRET);
    if (user) {
      const passwordValid = await bcrypt.compare(password, user.password);
      // console.log(passwordValid);
      if (!user.confirmed) {
        return ctx.throw(400, "Please confirm your account");
      }
      if (user.blocked) {
        return ctx.throw(400, "Your account has been blocked");
      }
      if (!passwordValid) {
        return ctx.throw(401, "Invalid password");
      }
      delete user.password;
      delete user.resetPasswordToken;
      delete user.confirmationToken;
      // console.log(user);
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_LIFETIME,
      });
      return ctx.send({
        jwt: token,
        user,
      });
    }
    const auth_Providers = await strapi.db
      .query("plugin::auth-provider.provider")
      .findMany({
        where: {
          sync_login: true,
        },
      });
    // console.log(auth_Providers);
    for (let i = 0; i < auth_Providers.length; i++) {
      let data = JSON.stringify({
        identifier,
        password,
      });

      let config = {
        method: auth_Providers[i].http_method,
        url: auth_Providers[i].endpoint,
        headers: {
          "Content-Type": "application/json",
        },
        data: data,
      };

      try {
        const checkUser = await axios(config);
        // console.log(checkUser.data);
        const { data } = checkUser;
        const salt = await bcrypt.genSalt(10);
        const encryptPassword = await bcrypt.hash(password, salt);
        // console.log(encryptPassword);
        // console.log(data.user);
        let userData = data.user;

        // creating user
        const createUser = await strapi.db
          .query("plugin::users-permissions.user")
          .create({
            data: {
              username: userData.username,
              email: userData.email,
              password: encryptPassword,
              provider: userData.provider,
              confirmed: userData.confirmed,
              blocked: userData.blocked,
              createdAt: userData.createdAt,
              updatedAt: userData.updatedAt,
            },
          });
        // console.log(createUser);
        return ctx.send(data);
      } catch (error) {
        // console.log(error);
        continue;
      }
    }
    // ctx.send(auth_Providers);
    return ctx.throw(400, "Invalid identifier or password");
  },
  async register(ctx) {
    const { username, email, password } = ctx.request.body;
    if (!username || !email || !password) {
      return ctx.throw(400, "Please provide username, email and password");
    }
    if (!validateEmail(email)) {
      return ctx.throw(400, "Please provide a valid email address");
    }
    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          $or: [
            {
              email,
            },
            {
              username,
            },
          ],
        },
      });
    if (user) {
      return ctx.throw(400, "Email or Username are already taken");
    }
    const salt = await bcrypt.genSalt(10);
    const encryptPassword = await bcrypt.hash(password, salt);
    const createUser = await strapi.db
      .query("plugin::users-permissions.user")
      .create({
        data: {
          username,
          email,
          password: encryptPassword,
          confirmed: true,
        },
      });
    const token = jwt.sign({ id: createUser.id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_LIFETIME,
    });

    const auth_Providers = await strapi.db
      .query("plugin::auth-provider.provider")
      .findMany({
        where: {
          sync_register: true,
        },
      });
    // console.log(auth_Providers);
    for (let i = 0; i < auth_Providers.length; i++) {
      let data = JSON.stringify({
        username,
        email,
        password,
      });

      let config = {
        method: auth_Providers[i].http_method,
        url: auth_Providers[i].endpoint,
        headers: {
          "Content-Type": "application/json",
        },
        data: data,
      };

      try {
        const newUser = await axios(config);
      } catch (error) {
        continue;
      }
    }

    delete createUser.password;
    delete createUser.resetPasswordToken;
    delete createUser.confirmationToken;
    return ctx.send({
      jwt: token,
      user: createUser,
    });
    // ctx.body = strapi
    //   .plugin("auth-provider")
    //   .service("myService")
    //   .getWelcomeMessage();
  },
  async forgotPassword(ctx) {
    const { email } = ctx.request.body;
    if (!email) {
      return ctx.throw(400, "Email is required");
    }
    if (!validateEmail(email)) {
      return ctx.throw(400, "Email is invalid");
    }
    const find = await strapi.db.query("plugin::users-permissions.user");
    if (!find) {
      return ctx.throw(400, "No user exists with given email");
    }
    const otp = (Math.floor(Math.random() * 899999) + 100000).toString();
    console.log(otp);

    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    await strapi.db.query("plugin::auth-provider.otp").delete({
      where: { email },
    });

    const createOTP = await strapi.db
      .query("plugin::auth-provider.otp")
      .create({
        data: {
          otp: hashedOTP,
          email,
          OTPExpireTime: Date.now() + 1 * 60 * 1000,
        },
      });

    const mail = {
      email: email,
      subject: "Forget Password OTP",
      html: `<h1>Forget Password OTP ${otp}</h1>`,
    };
    sendEmail(mail);

    return ctx.send({ msg: "OTP has been sent to email address" });
  },
  async resetPassword(ctx) {
    const { email, otp, password } = ctx.request.body;
    if (!otp) {
      return ctx.throw(400, "OTP is required");
    }
    if (!email) {
      return ctx.throw(400, "Email is required");
    }
    if (!password) {
      return ctx.throw(400, "Password is required");
    }

    const findOTP = await strapi.db.query("plugin::auth-provider.otp").findOne({
      where: { email, OTPExpireTime: { $gte: Date.now() } },
    });
    // console.log(findOTP);
    /* {
      id: 8,
      otp: '$2b$10$h9a4c/irahKdQOwPx637XehllpEhyM0lrS3gfptvizKkClU3gvzk.',
      email: 'sh.raheem222@gmail.com',
      OTPExpireTime: '2023-01-19T09:21:47.721Z',
      createdAt: '2023-01-19T09:20:47.722Z',
      updatedAt: '2023-01-19T09:20:47.722Z',
      publishedAt: null
    }    */
    if (!findOTP) {
      return ctx.throw(400, "Session expired");
    }
    const validOTP = await bcrypt.compare(otp, findOTP.otp);
    // console.log(validOTP);
    if (!validOTP) {
      return ctx.throw("Invalid otp");
    }
    await strapi.db.query("plugin::auth-provider.otp").delete({
      where: { email },
    });
    const salt = await bcrypt.genSalt(10);
    const encryptPassword = await bcrypt.hash(password, salt);

    await strapi.db.query("plugin::users-permissions.user").update({
      where: { email },
      data: { password: encryptPassword },
    });

    const auth_Providers = await strapi.db
      .query("plugin::auth-provider.provider")
      .findMany({
        where: {
          sync_password_reset: true,
        },
      });
    // console.log(auth_Providers);

    for (let i = 0; i < auth_Providers.length; i++) {
      try {
        const url = auth_Providers[i].endpoint;
        // console.log(url);
        const base_url = url.split("/")[0] + "//" + url.split("/")[2];
        // console.log(base_url);
        let getUsers = {
          method: "get",
          url: `${base_url}/api/users`,
          headers: {
            Authorization: `Bearer ${auth_Providers[i].token}`,
          },
        };
        const allUsers = await axios(getUsers);
        // console.log(allUsers.data);
        const findUser = allUsers.data.find((user) => user.email === email);
        // console.log(findUser.id);
        const { id } = findUser;
        // console.log(`${url}/${id}`);
        let data = JSON.stringify({
          password,
        });

        let config = {
          method: auth_Providers[i].http_method,
          url: `${url}/${id}`,
          headers: {
            Authorization: `Bearer ${auth_Providers[i].token}`,
            "Content-Type": "application/json",
          },
          data: data,
        };
        const updateUser = await axios(config);
        return ctx.send({ msg: "Password has been reset successfully" });
      } catch (error) {
        continue;
      }
    }
    return ctx.send({ msg: "Password has been reset successfully" });
  },
  async changePassword(ctx) {
    const { currentPassword, password, passwordConfirmation } =
      ctx.request.body;
    if (!currentPassword) {
      return ctx.throw(400, "Current password is required");
    }
    if (!password || !passwordConfirmation) {
      return ctx.throw(400, "New Password and confirmation is required");
    }
    const { authorization } = ctx.headers;
    if (!authorization || !authorization.startsWith("Bearer")) {
      return ctx.throw("Authentication Invalid");
    }
    const token = authorization.split(" ")[1];
    if (!token) {
      return ctx.throw("Authentication Invalid");
    }
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // console.log(payload);
    const { id } = payload;
    const findUser = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          id,
        },
      });
    // console.log(findUser);
    // console.log(findUser.password);
    const passwordValid = await bcrypt.compare(
      currentPassword,
      findUser.password
    );
    // console.log(passwordValid);
    if (!passwordValid) {
      return ctx.throw(400, "Password is invalid");
    }
    if (password !== passwordConfirmation) {
      return ctx.throw(400, "Password don't match.");
    }
    const salt = await bcrypt.genSalt(10);
    const encryptPassword = await bcrypt.hash(password, salt);
    await strapi.db.query("plugin::users-permissions.user").update({
      where: { id },
      data: { password: encryptPassword },
    });

    const auth_Providers = await strapi.db
      .query("plugin::auth-provider.provider")
      .findMany({
        where: {
          sync_password_update: true,
        },
      });
    for (let i = 0; i < auth_Providers.length; i++) {
      const url = auth_Providers[i].endpoint;
      // console.log(url);
      const base_url = url.split("/")[0] + "//" + url.split("/")[2];
      let oldData = JSON.stringify({
        identifier: findUser.email,
        password: currentPassword,
      });

      let login = {
        method: "post",
        url: `${base_url}/api/auth/local`,
        headers: {
          "Content-Type": "application/json",
        },
        data: oldData,
      };
      try {
        const userData = await axios(login);
        // console.log(userData.data.jwt);
        // console.log(userData.data.user);
        const { jwt } = userData.data;
        var data = JSON.stringify({
          currentPassword,
          password,
          passwordConfirmation,
        });

        var config = {
          method: auth_Providers[i].http_method,
          url: auth_Providers[i].endpoint,
          headers: {
            Authorization: `Bearer ${jwt}`,
            "Content-Type": "application/json",
          },
          data: data,
        };

        await axios(config);
      } catch (error) {
        continue;
      }
    }
    // console.log(auth_Providers);
    return ctx.send({ msg: "Password has been reset successfully" });
  },
});
