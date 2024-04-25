import jwt from "jsonwebtoken";
import { createError } from "../utils/error.js";

export const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) {
    return next(createError(401, "You are not authenticated!"));
  }

  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) return next(createError(403, "Token is not valid!"));
    req.user = user;
    next();
  });
};

export const verifyUser = (req, res, next) => {
  verifyToken(req, res, (err) => {
    if (err) {
      return next(err); // Handle any token verification error
    }

    if (req.user.id === req.params.id || req.user.isAdmin) {
      next(); // User is authorized
    } else {
      return next(createError(403, "You are not authorized!")); // Authorization error
    }
  });
};


export const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, (err) => {
    if (err) {
      return next(err); // Handle token verification error
    }

    if (req.user.isAdmin) {
      next(); // User is an admin, proceed
    } else {
      return next(createError(403, "You are not authorized!")); // Not an admin
    }
  });
};
