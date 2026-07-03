import type { Context } from "hono"
import { HTTPException } from "hono/http-exception"

/**
 * Bitwarden-compatible error envelopes, ported from vaultwarden src/error.rs.
 *
 * The "full" envelope is what `err!()` produces; clients surface
 * `errorModel.message`. The identity endpoint additionally uses raw OAuth2
 * bodies (`{"error": "invalid_grant", ...}`) for protocol-level failures.
 */

export function errorBody(message: string) {
	return {
		message,
		validationErrors: { "": [message] },
		errorModel: { message, object: "error" },
		error: "",
		error_description: "",
		exceptionMessage: null,
		exceptionStackTrace: null,
		innerExceptionMessage: null,
		object: "error"
	}
}

export function compactErrorBody(message: string) {
	return {
		message,
		validationErrors: null,
		exceptionMessage: null,
		exceptionStackTrace: null,
		innerExceptionMessage: null,
		object: "error"
	}
}

export class ApiError extends Error {
	constructor(
		message: string,
		readonly status: 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500 = 400,
		/** Raw JSON body override (e.g. OAuth2 errors, TwoFactorRequired payload). */
		readonly body?: Record<string, unknown>
	) {
		super(message)
	}
}

/** Standard 400 with the full envelope — vaultwarden's `err!()`. */
export function err(message: string): never {
	throw new ApiError(message, 400)
}

export function errCode(message: string, status: ApiError["status"]): never {
	throw new ApiError(message, status)
}

/** Identity endpoint OAuth2-style error — vaultwarden's `err_json!()`. */
export function errJson(
	body: Record<string, unknown>,
	message = "error",
	status: ApiError["status"] = 400
): never {
	throw new ApiError(message, status, body)
}

export function notFound(message = "Not found"): never {
	throw new ApiError(message, 404)
}

export function unauthorized(message = "Unauthorized"): never {
	throw new ApiError(message, 401)
}

export function onError(e: Error, c: Context) {
	if (e instanceof ApiError) {
		if (e.body) return c.json(e.body, e.status)
		return c.json(errorBody(e.message), e.status)
	}
	if (e instanceof HTTPException) {
		return c.json(errorBody(e.message || "Request error"), e.status as 400)
	}
	console.error("Unhandled error:", e.stack ?? e)
	return c.json(errorBody("Internal server error"), 500)
}
