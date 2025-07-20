import httpStatus from "http-status-codes";
import { Request, Response } from "express";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";
import { AuthService } from "./auth.service";
import AppError from "../../errorHelpers/AppError";
import { setAuthCooke } from "../../utils/setCooke";

const credentialsLogin = catchAsync(async (req: Request, res: Response) => {
  const logInInfo = await AuthService.credentialsLogin(req.body);

  setAuthCooke(res, logInInfo);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Login Successfully",
    data: logInInfo,
  });
});
const getNewAccessToken = catchAsync(async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    throw new AppError(httpStatus.BAD_REQUEST, "No Token received");
  }
  const tokenInfo = await AuthService.getNewAccessToken(refreshToken as string);

  setAuthCooke(res, tokenInfo);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "New Access Token Successfully",
    data: tokenInfo,
  });
});
const logOut = catchAsync(async (req: Request, res: Response) => {
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Log out Successfully",
    data: null,
  });
});
const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const decodedToken = req.user;
  const newPassword = req.body.newPassword;
  const oldPassword = req.body.oldPassword;

  await AuthService.resetPassword(oldPassword, newPassword, decodedToken);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: "Password Change Successfully",
    data: null,
  });
});

export const AuthController = {
  credentialsLogin,
  getNewAccessToken,
  logOut,
  resetPassword,
};
