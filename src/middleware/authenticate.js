const { admin } = require("../config/firebase");
const db = require("../config/db");

/**
 * Normalizes a role string to lowercase: "user", "agent", or "admin".
 * Defaults to "user" if absent or unrecognized.
 */
const normalizeRole = (role) => {
  if (!role || typeof role !== "string") return "user";
  const lower = role.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (lower === "admin" || lower === "super_admin") {
    return "admin";
  }
  if (lower === "agent") {
    return "agent";
  }
  return "user";
};

/**
 * Firebase ID Token Authentication Middleware
 *
 * Verifies the Firebase ID Token (JWT) sent via Authorization header.
 * - Expects: Authorization: Bearer <Firebase-ID-Token>
 * - Verifies using: admin.auth().verifyIdToken(token, true) (enforcing revocation check)
 * - Rejects missing, malformed, invalid, expired, or revoked tokens with HTTP 401
 * - Attaches decoded user to req.user (uid, email, email_verified, role, claims, dbId)
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || typeof authHeader !== "string") {
      return res.status(401).json({
        success: false,
        message: "Authentication required: Missing Authorization header.",
      });
    }

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required: Malformed Authorization header. Expected 'Bearer <token>'.",
      });
    }

    const token = authHeader.split("Bearer ")[1]?.trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required: Token is missing.",
      });
    }

    // Verify token with Firebase Admin SDK and check for token revocation
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(token, true);
    } catch (verifyError) {
      // Handle Firebase specific error codes
      let message = "Invalid or expired authentication token.";
      if (verifyError.code === "auth/id-token-expired") {
        message = "Authentication token has expired. Please refresh your session.";
      } else if (verifyError.code === "auth/id-token-revoked") {
        message = "Authentication token has been revoked. Please sign in again.";
      } else if (verifyError.code === "auth/argument-error") {
        message = "Malformed authentication token format.";
      }

      return res.status(401).json({
        success: false,
        message,
      });
    }

    // Determine normalized lowercase role from verified custom claims
    let verifiedRole = normalizeRole(decodedToken.role);

    // Attach verified user identity to req.user
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email || null,
      email_verified: !!decodedToken.email_verified,
      role: verifiedRole,
      claims: decodedToken,
      // Provide legacy uid alias for full compatibility
      id: decodedToken.uid,
    };

    // Lookup / sync corresponding PostgreSQL user for DB relations
    try {
      let dbUserRes = await db.query(
        "SELECT id, name, email, role, role_category_id FROM users WHERE firebase_uid = $1",
        [decodedToken.uid]
      );

      if (dbUserRes.rows.length === 0 && decodedToken.email) {
        dbUserRes = await db.query(
          "SELECT id, name, email, role, role_category_id FROM users WHERE LOWER(email) = LOWER($1)",
          [decodedToken.email]
        );

        if (dbUserRes.rows.length > 0) {
          // Link firebase_uid to existing user record
          await db.query(
            "UPDATE users SET firebase_uid = $1 WHERE id = $2",
            [decodedToken.uid, dbUserRes.rows[0].id]
          );
        } else {
          // Auto-provision user record in PostgreSQL if missing
          const insertRes = await db.query(
            "INSERT INTO users (name, email, role, firebase_uid) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, role_category_id",
            [
              decodedToken.name || decodedToken.email.split("@")[0],
              decodedToken.email,
              verifiedRole,
              decodedToken.uid,
            ]
          );
          dbUserRes = insertRes;
        }
      }

      if (dbUserRes.rows.length > 0) {
        const dbUser = dbUserRes.rows[0];
        req.user.dbId = dbUser.id;
        req.user.dbUser = dbUser;

        const dbRole = normalizeRole(dbUser.role);
        // If Firebase custom claim was missing or default "user", but DB has an assigned role (admin/agent):
        if (!decodedToken.role || (decodedToken.role === "user" && dbRole !== "user")) {
          req.user.role = dbRole;
          // Synchronize to Firebase custom claims asynchronously
          admin
            .auth()
            .setCustomUserClaims(decodedToken.uid, { role: dbRole })
            .catch((err) => {
              console.warn("Auto-syncing custom claims to Firebase warning:", err.message);
            });
        }
      }
    } catch (dbErr) {
      console.error("User DB lookup warning in auth middleware:", dbErr.message);
    }

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Authentication failed.",
    });
  }
};

module.exports = authenticate;
