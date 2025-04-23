import { Router } from "express";
import { 
  registerUser, 
  verifyEmail, 
  loginUser,
  logoutUser,
  getCurrentUser,
  changeCurrentPassword,
  forgotPasswordRequest,
  resetForgottenPassword,
  resendEmailVerification,
  refreshAccessToken
} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { 
  registerValidator,
  loginValidator,
  changePasswordValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  resendEmailVerificationValidator
} from "../validators/index.js";

const router = Router();

// Public routes
router.route("/register")
  .post(registerValidator(), validate, registerUser);

router.route("/login")
  .post(loginValidator(), validate, loginUser);

router.route("/verify-email/:token")
  .get(verifyEmail);

router.route("/resend-email-verification")
  .post(resendEmailVerificationValidator(), validate, resendEmailVerification);

router.route("/forgot-password")
  .post(forgotPasswordValidator(), validate, forgotPasswordRequest);

router.route("/reset-password/:token")
  .post(resetPasswordValidator(), validate, resetForgottenPassword);

router.route("/refresh-token")
  .post(refreshAccessToken);

// Protected routes (require authentication)
router.route("/logout")
  .post(verifyJWT, logoutUser);

router.route("/change-password")
  .post(verifyJWT, changePasswordValidator(), validate, changeCurrentPassword);

router.route("/current-user")
  .get(verifyJWT, getCurrentUser);

export default router;
