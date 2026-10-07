import http from "../utils/http.js";
import { OAuth2Client } from "google-auth-library";
import { env } from "../config/env.js";
import { HttpError } from "../utils/http-error.js";
import { signAccessToken, signRefreshToken } from "../utils/jwt.js";
import { getOrCreateUserByEmail } from "./store.js";

const googleClient = env.GOOGLE_CLIENT_ID ? new OAuth2Client(env.GOOGLE_CLIENT_ID) : null;

export async function loginWithGoogleCredential(credential) {
  if (!credential) {
    throw new HttpError(400, "Google credential is required");
  }
  if (!googleClient || !env.GOOGLE_CLIENT_ID) {
    throw new HttpError(500, "GOOGLE_CLIENT_ID is not configured in backend env");
  }

  let ticket;
  try {
    ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: env.GOOGLE_CLIENT_ID
    });
  } catch (error) {
    throw new HttpError(401, "Invalid Google credential or origin/client mismatch", {
      provider: "google",
      reason: error?.message || "verifyIdToken failed"
    });
  }

  const payload = ticket.getPayload();
  if (!payload?.email) {
    throw new HttpError(401, "Unable to verify Google account email");
  }

  const user = await getOrCreateUserByEmail({
    email: payload.email,
    name: payload.name || payload.given_name || payload.email,
    picture: payload.picture || ""
  });

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  return {
    user,
    accessToken,
    refreshToken
  };
}
export async function loginWithGoogleAccessToken(googleAccessToken) {
  if (!googleAccessToken) {
    throw new HttpError(400, "Google access token is required");
  }

  let profile;
  try {
    const response = await http.get("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${googleAccessToken}` },
      timeout: 10000,
    });
    profile = response.data;
  } catch (error) {
    throw new HttpError(401, "Invalid Google access token", {
      provider: "google",
      reason: error?.response?.data || error?.message || "userinfo lookup failed",
    });
  }

  if (!profile?.email) {
    throw new HttpError(401, "Unable to read Google account email");
  }

  const user = await getOrCreateUserByEmail({
    email: profile.email,
    name: profile.name || profile.given_name || profile.email,
    picture: profile.picture || "",
  });

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  return {
    user,
    accessToken,
    refreshToken,
  };
}

