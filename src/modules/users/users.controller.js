const usersService = require("./users.service");
const { isValidRole, normalizeRole, VALID_ROLES } = require("../../services/firebaseAuth.service");
const firebaseAuthService = require("../../services/firebaseAuth.service");

// Simple email regex for fast validation
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * POST /api/users - Create a new user (prevents self-service admin promotion)
 */
const createUser = async (req, res, next) => {
  try {
    const { name, email, role } = req.body;
    const authUser = req.user;

    // Use verified identity email if available
    const resolvedEmail = authUser?.email || email;

    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: "name is required and must be a valid non-empty string.",
      });
    }

    if (!resolvedEmail || typeof resolvedEmail !== "string" || !EMAIL_REGEX.test(resolvedEmail.trim())) {
      return res.status(400).json({
        success: false,
        message: "Valid email address is required.",
      });
    }

    // Role security: Never allow self-service role assignment.
    // Only an authenticated admin can specify a role other than "user".
    let assignedRole = "user";
    if (authUser && authUser.role === "admin" && role && isValidRole(role)) {
      assignedRole = normalizeRole(role);
    }

    // Check if user already exists
    const existingUser = await usersService.getUserByEmail(resolvedEmail.trim());
    if (existingUser) {
      // Link firebase_uid if available and not yet set
      if (authUser?.uid && !existingUser.firebase_uid) {
        await usersService.updateUser(existingUser.id, {
          firebase_uid: authUser.uid,
        });
      }
      return res.status(200).json({
        success: true,
        message: "User already exists",
        data: existingUser,
      });
    }

    const user = await usersService.createUser({
      name,
      email: resolvedEmail,
      role: assignedRole,
      firebase_uid: authUser?.uid || null,
    });

    res.status(201).json({
      success: true,
      message: "User created successfully",
      data: user,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/users - Get all users (supports pagination, role filtering & search)
 * Regular users may only access their own profile.
 */
const getAllUsers = async (req, res, next) => {
  try {
    const authUser = req.user;

    // Email-specific profile query
    if (req.query.email) {
      if (authUser && authUser.role === "user") {
        const emailQuery = req.query.email?.trim().toLowerCase();
        const userEmail = authUser.email?.trim().toLowerCase();

        if (emailQuery !== userEmail) {
          return res.status(403).json({
            success: false,
            message: "Forbidden: Regular users can only access their own profile.",
          });
        }
      }
      return getUserbyEmail(req, res, next);
    }

    // Regular users cannot manage or enumerate all users; only staff (agents/admins) for ticket assignment display
    if (authUser && authUser.role === "user") {
      const db = require("../../config/db");
      const staffQuery = `
        SELECT id, name, email, role, role_category_id, created_at
        FROM users
        WHERE LOWER(role) IN ('agent', 'admin')
        ORDER BY id ASC
      `;
      const staffResult = await db.query(staffQuery);
      return res.json({
        success: true,
        total: staffResult.rows.length,
        data: staffResult.rows,
      });
    }

    const result = await usersService.getAllUsers(req.query);

    res.json({
      success: true,
      ...result,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/users?email=xxx - Get user by email
 */
const getUserbyEmail = async (req, res) => {
  const { email } = req.query;

  if (!email || typeof email !== "string" || !email.trim()) {
    return res.status(400).json({
      success: false,
      message: "Email query parameter is required.",
    });
  }

  const user = await usersService.getUserByEmail(email);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  res.json({
    success: true,
    data: user,
  });
};

/**
 * GET /api/users/:id - Get user by ID
 */
const getUserById = async (req, res) => {
  const user = await usersService.getUserById(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  res.json({
    success: true,
    data: user,
  });
};

/**
 * PUT /api/users/:id - Update user details
 */
const updateUser = async (req, res) => {
  const { name, email, role } = req.body;

  if (
    email !== undefined &&
    (!email || typeof email !== "string" || !EMAIL_REGEX.test(email.trim()))
  ) {
    return res.status(400).json({
      success: false,
      message: "Provided email address is invalid.",
    });
  }

  if (name !== undefined && (typeof name !== "string" || !name.trim())) {
    return res.status(400).json({
      success: false,
      message: "name cannot be empty.",
    });
  }

  if (role !== undefined && !isValidRole(role)) {
    return res.status(400).json({
      success: false,
      message: `Invalid role '${role}'. Role must be one of: ${VALID_ROLES.join(", ")}.`,
    });
  }

  const user = await usersService.updateUser(req.params.id, {
    name,
    email,
    role: role !== undefined ? normalizeRole(role) : undefined,
  });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  if (role !== undefined && user.firebase_uid) {
    const { admin } = require("../../config/firebase");
    admin
      .auth()
      .setCustomUserClaims(user.firebase_uid, { role: normalizeRole(role) })
      .catch((e) => console.warn("Failed to sync role to Firebase in updateUser:", e.message));
  }

  res.json({
    success: true,
    message: "User updated successfully",
    data: user,
  });
};

/**
 * DELETE /api/users/:id - Delete a user
 */
const deleteUser = async (req, res) => {
  const user = await usersService.deleteUser(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  res.json({
    success: true,
    message: "User deleted successfully",
    data: user,
  });
};

/**
 * PATCH /api/users/:id/role - Update user role in Firebase custom claims & PostgreSQL (Admin only)
 */
const updateUserRole = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || typeof role !== "string" || !isValidRole(role)) {
      return res.status(400).json({
        success: false,
        message: `Invalid role '${role}'. Role must be one of: ${VALID_ROLES.join(", ")}.`,
      });
    }

    const normalizedRole = normalizeRole(role);

    // Resolve target user: id could be integer (PostgreSQL id) or Firebase UID
    let targetUid = null;
    let dbUser = null;

    if (!isNaN(Number(id))) {
      dbUser = await usersService.getUserById(parseInt(id, 10));
      if (!dbUser) {
        return res.status(404).json({
          success: false,
          message: `User with ID ${id} not found in database.`,
        });
      }
      if (dbUser.firebase_uid) {
        targetUid = dbUser.firebase_uid;
      } else if (dbUser.email) {
        try {
          const fbUser = await firebaseAuthService.getUserByEmail(dbUser.email);
          targetUid = fbUser.uid;
        } catch (e) {
          // Firebase user not found by email
        }
      }
    } else {
      // id is a Firebase UID
      targetUid = id;
      try {
        const fbUser = await firebaseAuthService.getUserByUid(id);
        targetUid = fbUser.uid;
      } catch (e) {
        // Continue with id as UID
      }
    }

    if (!targetUid) {
      return res.status(404).json({
        success: false,
        message: `Could not resolve target Firebase UID for user '${id}'.`,
      });
    }

    // Set custom claims in Firebase & sync with DB
    await firebaseAuthService.setRole(targetUid, normalizedRole);

    // Fetch updated user from DB
    const updatedDbUser = dbUser
      ? await usersService.getUserById(dbUser.id)
      : await usersService.getUserByEmail(id);

    return res.status(200).json({
      success: true,
      message: `User role successfully updated to '${normalizedRole}'.`,
      data: {
        uid: targetUid,
        role: normalizedRole,
        user: updatedDbUser,
      },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createUser,
  getAllUsers,
  getUserById,
  getUserbyEmail,
  getUserByEmail: getUserbyEmail,
  updateUser,
  updateUserRole,
  deleteUser,
};
