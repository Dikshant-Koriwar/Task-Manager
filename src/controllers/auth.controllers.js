import { asyncHandler } from "../utils/async-handler.js";
import User from "../models/user.models.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { sendEmail } from "../utils/mail.js";
import { emailVerificationMailgenContent, forgotPasswordMailgenContent } from "../utils/mail.js";
import crypto from "crypto";
import { generateAccessAndRefreshToken } from "../utils/generate-acess-refresh.js";
import jwt from "jsonwebtoken";

const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body;

  if (!fullName || !email || !username || !password) {
    throw new ApiError(400, "All fields are required");
  }

  // Check both email and username for existing users
  const existingUser = await User.findOne({
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    const field = existingUser.email === email ? "email" : "username";
    throw new ApiError(409, `User with this ${field} already exists`);
  }

  const user = await User.create({
    fullName,
    email,
    username,
    password,
  });

  const {unHashedToken, hashedToken, tokenExpiry} = user.generateTemporaryToken();
  
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  await user.save();

  try {
    await sendEmail({
      email: user.email,
      subject: "Please verify your email",
      mailgenContent: emailVerificationMailgenContent(
        user.username,
        `${process.env.BASE_URL}/api/v1/users/verify-email/${unHashedToken}`,
      ),
    });

    return res
      .status(201)
      .json(
        new ApiResponse(
          201,
          { user },
          "Users registered successfully and verification email has been sent on your email.",
        ),
      );
  } catch (error) {
    // If email fails, we should still return success but with a different message
    return res
      .status(201)
      .json(
        new ApiResponse(
          201,
          { user },
          "Users registered successfully but there was an issue sending the verification email. Please contact support.",
        ),
      );
  }
});


const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.params;
  
  // Hash the token from URL to match what's stored in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const user = await User.findOne({ 
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() }
  });

  if (!user) {
    throw new ApiError(404, "Invalid or expired verification token");
  }

  // Mark email as verified
  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  await user.save();

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user },
        "Email verified successfully.",
      ),
    );    
});
// login the user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  console.log("LoginStarts : ", req.body);

  try {
    // 1. get the user from the database
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      throw new ApiError(400, "Invalid Email or Password");
    }

    // 2. verify user's email
    if (!user.isEmailVerified) {
      throw new ApiError(400, "Please verify your email first");
    }

    // 3. validate password
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
      throw new ApiError(400, "Invalid Email or Password");
    }

    // 4. generate access and refresh tokens
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
      user._id,
    );

    // 5. get user without sensitive info
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    // 6. set cookies
    const options = {
      httpOnly: true,
      secure: true,
    };
    res.cookie("accessToken", accessToken, options);
    res.cookie("refreshToken", refreshToken, options);

    // 7. send response
    return res
      .status(200)
      .json(new ApiResponse(200, { user: loggedInUser }, "Logged in Successfully"));
  } catch (error) {
    throw new ApiError(400, error?.message || "Login Failed");
  }
});

// get the user information
const getCurrentUser = asyncHandler(async (req, res) => {
  try {
    const user = req.user;
    if (!user) {
      throw new ApiError(401, "Unauthorized request");
    }

    // Get fresh user data without sensitive fields
    const currentUser = await User.findById(user._id).select("-password -refreshToken");
    if (!currentUser) {
      throw new ApiError(404, "User not found");
    }

    return res
      .status(200)
      .json(new ApiResponse(200, { user: currentUser }, "User fetched successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Error fetching user details");
  }
});

// logout the user
const logoutUser = asyncHandler(async (req, res) => {
  try {
    const user = req.user;
    if (!user) {
      throw new ApiError(401, "Unauthorized request");
    }

    // Clear refresh token in DB
    await User.findByIdAndUpdate(
      user._id,
      {
        $unset: { refreshToken: 1 }
      },
      {
        new: true
      }
    );

    // Clear cookies
    const options = {
      httpOnly: true,
      secure: true
    };
    
    res
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .status(200)
      .json(new ApiResponse(200, {}, "Logged out successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message || "Error during logout");
  }
});

// resend verification email
const resendEmailVerification = asyncHandler(async (req, res) => {
  try {
    // 1. Get email from request
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, "Email is required");
    }

    // 2. Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    // 3. Check if email is already verified
    if (user.isEmailVerified) {
      throw new ApiError(400, "Email is already verified");
    }

    // 4. Check if previous token hasn't expired yet
    if (user.emailVerificationExpiry && user.emailVerificationExpiry > Date.now()) {
      const timeLeft = Math.ceil((user.emailVerificationExpiry - Date.now()) / 1000 / 60); // in minutes
      throw new ApiError(429, `Please wait ${timeLeft} minutes before requesting another verification email`);
    }

    // 5. Generate verification token
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    // 6. Save the new token and expiry
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save();

    // 7. Generate verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${unHashedToken}`;

    // 8. Send verification email
    try {
      await sendEmail({
        email: user.email,
        subject: "Verify your email",
        mailgenContent: {
          body: {
            name: user.username,
            intro: "Welcome! Please verify your email address to complete your registration.",
            action: {
              instructions: "Click the button below to verify your email:",
              button: {
                color: "#22BC66",
                text: "Verify your email",
                link: verificationUrl,
              },
            },
            outro: "If you did not create an account, no further action is required.",
          },
        },
      });

      // 9. Return success response
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "Verification email sent successfully"));
    } catch (emailError) {
      // 10. If email fails, reset the tokens
      user.emailVerificationToken = undefined;
      user.emailVerificationExpiry = undefined;
      await user.save();
      throw new ApiError(500, "Error sending verification email, please try again");
    }
  } catch (error) {
    throw new ApiError(error.statusCode || 500, error?.message || "Error sending verification email");
  }
});

// change the current password
const changeCurrentPassword = asyncHandler(async (req, res) => {
  try {
    //1. get loggedIn user with password
    const user = await User.findById(req.user?._id).select("+password");
    if (!user) {
      throw new ApiError(401, "Unauthorized request");
    }

    //2. get old and new password
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      throw new ApiError(400, "Both old and new password are required");
    }

    if (oldPassword === newPassword) {
      throw new ApiError(400, "New password must be different from old password");
    }

    //3. Verify old password
    const isPasswordValid = await user.isPasswordCorrect(oldPassword);
    if (!isPasswordValid) {
      throw new ApiError(400, "Invalid old password");
    }

    //4. Update password
    user.password = newPassword;
    await user.save({ validateBeforeSave: true });

    // 5. Send response
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password changed successfully"));
  } catch (error) {
    throw new ApiError(error.statusCode || 500, error?.message || "Error changing password");
  }
});

// forgotten Password
const forgotPasswordRequest = asyncHandler(async (req, res) => {
  try {
    //1. Get email from user
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, "Email is required");
    }

    //2. Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    //3. Generate temporary token
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    //4. Save token to user
    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;
    await user.save();

    //5. Create reset url
    const resetUrl = `${process.env.BASE_URL}/api/v1/users/reset-password/${unHashedToken}`;

    //6. Send email
    try {
      await sendEmail({
        email: user.email,
        subject: "Reset your password",
        mailgenContent: {
          body: {
            name: user.username,
            intro: "You have received this email because a password reset request for your account was received.",
            action: {
              instructions: "Click the button below to reset your password:",
              button: {
                color: "#22BC66",
                text: "Reset your password",
                link: resetUrl,
              },
            },
            outro: "If you did not request a password reset, no further action is required on your part.",
          },
        },
      });

      //7. Send response
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password reset link sent to email"));
    } catch (error) {
      user.forgotPasswordToken = undefined;
      user.forgotPasswordExpiry = undefined;
      await user.save();
      throw new ApiError(500, "Error sending email, please try again");
    }
  } catch (error) {
    throw new ApiError(500, error?.message || "Error processing password reset request");
  }
});

// reset forgotten password
const resetForgottenPassword = asyncHandler(async (req, res) => {
  try {
    //1. Get token and new password
    const { token } = req.params;
    const { newPassword } = req.body;
    if (!token || !newPassword) {
      throw new ApiError(400, "Token and new password are required");
    }

    //2. Hash the token
    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    //3. Find user with valid token
    const user = await User.findOne({
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: { $gt: Date.now() }
    }).select("+password +forgotPasswordToken +forgotPasswordExpiry");

    if (!user) {
      throw new ApiError(400, "Token is invalid or has expired");
    }

    // Check if token is expired
    if (user.forgotPasswordExpiry < Date.now()) {
      user.forgotPasswordToken = undefined;
      user.forgotPasswordExpiry = undefined;
      await user.save();
      throw new ApiError(400, "Reset token has expired. Please request a new one.");
    }

    //4. Update password and clear reset token
    user.password = newPassword;
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: true });

    //5. Send success email
    try {
      await sendEmail({
        email: user.email,
        subject: "Password Reset Successful",
        mailgenContent: {
          body: {
            name: user.username,
            intro: "Your password has been successfully reset.",
            outro: "If you did not perform this action, please contact support immediately."
          }
        }
      });
    } catch (emailError) {
      // Log error but don't fail the request
      console.error("Error sending password reset confirmation:", emailError);
    }

    //6. Send response
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password reset successful"));
  } catch (error) {
    throw new ApiError(error.statusCode || 500, error?.message || "Error resetting password");
  }
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken = req.cookies?.refreshToken;
    if (!incomingRefreshToken) {
      throw new ApiError(401, "Unauthorized request: Missing refresh token");
    }

    // Verify the token
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // Get user and validate token
    const user = await User.findById(decodedToken?._id).select("+refreshToken");
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    // Generate new tokens
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    // Set cookies
    const options = {
      httpOnly: true,
      secure: true
    };

    return res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .status(200)
      .json(
        new ApiResponse(
          200,
          { user: { _id: user._id, email: user.email, username: user.username } },
          "Access token refreshed"
        )
      );
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new ApiError(401, "Invalid refresh token");
    }
    if (error.name === "TokenExpiredError") {
      throw new ApiError(401, "Refresh token has expired");
    }
    throw new ApiError(500, error?.message || "Error refreshing access token");
  }
});

export {
  changeCurrentPassword,
  forgotPasswordRequest,
  getCurrentUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendEmailVerification,
  resetForgottenPassword,
  verifyEmail,
};
