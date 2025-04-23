import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";
import User from "../models/user.models.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized request");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        
        // Use lean() for better performance since we don't need a full mongoose document
        const user = await User.findById(decodedToken?._id)
            .select("-password -refreshToken")
            .lean();

        if (!user) {
            throw new ApiError(401, "Invalid Access Token");
        }

        req.user = user;
        next();
    } catch (error) {
        // Handle specific JWT errors
        if (error.name === "JsonWebTokenError") {
            throw new ApiError(401, "Invalid access token");
        }
        if (error.name === "TokenExpiredError") {
            throw new ApiError(401, "Access token has expired");
        }
        // Handle connection errors
        if (error.code === 'ECONNRESET') {
            throw new ApiError(500, "Connection error, please try again");
        }
        throw new ApiError(401, error?.message || "Invalid access token");
    }
});
