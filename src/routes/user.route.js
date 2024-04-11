import express from "express";
import {
  login,
  register,
  refreshAccessToken,
  logout,
  verification,
  updateProfile
} from "../controllers/user.controller.js";
import { auth } from "../middleware/auth.middleware.js ";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refreshAccessToken", refreshAccessToken);
router.post("/logout", auth, logout);
router.post("/verification", verification);
router.post("/profileUpdate", auth,updateProfile);

export default router;
