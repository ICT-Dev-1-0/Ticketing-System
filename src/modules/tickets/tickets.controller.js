const ticketsService = require("./tickets.service");
const {
  validateCreateTicket,
  validateUpdateStatus,
  validateUpdateTicket,
} = require("./tickets.validation");

/**
 * POST /api/tickets - Create a new ticket
 * Security: Uses req.user.uid as ticket creator, never trusting client-supplied userId
 */
const createTicket = async (req, res, next) => {
  try {
    // Always bind creator identity to authenticated Firebase user UID
    const payload = {
      ...req.body,
      user_id: req.user.uid,
    };

    const validation = validateCreateTicket(payload);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        errors: validation.errors,
      });
    }

    const ticket = await ticketsService.createTicket(payload);

    res.status(201).json({
      success: true,
      message: "Ticket created successfully",
      data: ticket,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/tickets - Get tickets with filters and pagination
 * Security: USER role is strictly scoped to own tickets, ignoring client overrides
 */
const getTickets = async (req, res, next) => {
  try {
    const authUser = req.user;
    const {
      status,
      priority,
      department_id,
      help_topic_id,
      assigned_to,
      page = 1,
      limit = 20,
    } = req.query;

    let queryUserId = req.query.user_id;
    let queryEmail = req.query.email;

    // Enforce ownership filter for standard USER role
    if (authUser && authUser.role === "user") {
      queryUserId = authUser.uid;
      queryEmail = undefined;
    }

    const tickets = await ticketsService.getTickets({
      status,
      priority,
      department_id,
      help_topic_id,
      user_id: queryUserId,
      email: queryEmail,
      assigned_to,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
    });

    res.json({
      success: true,
      count: tickets.length,
      data: tickets,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/tickets/my - Explicit endpoint to fetch authenticated user's tickets
 */
const getMyTickets = async (req, res, next) => {
  try {
    const authUser = req.user;
    const { status, priority, page = 1, limit = 50 } = req.query;

    const tickets = await ticketsService.getTickets({
      status,
      priority,
      user_id: authUser.uid,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
    });

    res.json({
      success: true,
      count: tickets.length,
      data: tickets,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/tickets/assigned - Fetch tickets assigned to the authenticated agent
 */
const getAssignedTickets = async (req, res, next) => {
  try {
    const authUser = req.user;
    const targetAssignedTo =
      authUser.role === "admin" && req.query.assigned_to
        ? req.query.assigned_to
        : authUser.dbId;

    const tickets = await ticketsService.getTickets({
      status: req.query.status,
      priority: req.query.priority,
      assigned_to: targetAssignedTo,
      page: parseInt(req.query.page || 1, 10),
      limit: parseInt(req.query.limit || 50, 10),
    });

    res.json({
      success: true,
      count: tickets.length,
      data: tickets,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/tickets?email=xxx - Get tickets by user email
 */
const getTicketsByEmail = async (req, res, next) => {
  try {
    const { email } = req.query;

    if (!email || typeof email !== "string" || !email.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email query parameter is required.",
      });
    }

    return await getTickets(req, res, next);
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/tickets/:id - Get ticket by ID or Ticket Number
 * Security: Enforces ownership check - USER role cannot access other users' tickets
 */
const getTicketById = async (req, res, next) => {
  try {
    const ticket = await ticketsService.getTicketById(req.params.id);
    if (!ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    // Ownership check for USER role
    if (req.user && req.user.role === "user") {
      const isOwner =
        ticket.user_id === req.user.uid ||
        (req.user.dbId && ticket.user_id === String(req.user.dbId));

      if (!isOwner) {
        return res.status(403).json({
          success: false,
          message: "Forbidden: You do not have permission to access another user's ticket.",
        });
      }
    }

    res.json({
      success: true,
      data: ticket,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * PATCH /api/tickets/:id/status - Update ticket status
 */
const updateTicketStatus = async (req, res, next) => {
  try {
    const validation = validateUpdateStatus(req.body);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        errors: validation.errors,
      });
    }

    const updatedTicket = await ticketsService.updateTicketStatus(
      req.params.id,
      req.body.status
    );

    if (!updatedTicket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    res.json({
      success: true,
      message: "Ticket status updated successfully",
      data: updatedTicket,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * PATCH /api/tickets/:id - Full or partial update of ticket fields
 */
const updateTicket = async (req, res, next) => {
  try {
    const payload = { ...req.body };
    if (payload.assignedToId !== undefined && payload.assigned_to === undefined) {
      payload.assigned_to = payload.assignedToId;
    }

    const validation = validateUpdateTicket(payload);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        errors: validation.errors,
      });
    }

    const updatedTicket = await ticketsService.updateTicket(
      req.params.id,
      payload
    );

    if (!updatedTicket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    res.json({
      success: true,
      message: "Ticket updated successfully",
      data: updatedTicket,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * PATCH /api/tickets/:id/assign - Assign ticket
 */
const assignTicket = async (req, res, next) => {
  try {
    const rawAssigned =
      req.body.assignedToId !== undefined ? req.body.assignedToId : req.body.assigned_to;

    const targetUserId =
      rawAssigned === null || rawAssigned === 0 || rawAssigned === "0"
        ? null
        : parseInt(rawAssigned, 10);

    if (rawAssigned !== undefined && rawAssigned !== null && rawAssigned !== 0 && isNaN(targetUserId)) {
      return res.status(400).json({
        success: false,
        message: "assignedToId / assigned_to must be an integer ID or null.",
      });
    }

    // Extract note — null it out when unassigning
    const assignmentNote = targetUserId === null ? null : (req.body.assignment_note ?? null);

    const updatedTicket = await ticketsService.assignTicket(
      req.params.id,
      targetUserId,
      assignmentNote
    );

    if (!updatedTicket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    res.json({
      success: true,
      message: "Ticket assignment updated successfully",
      data: updatedTicket,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * DELETE /api/tickets/:id - Delete a ticket
 * Rules:
 * - Admin/Agent: Can delete ticket
 * - User: Can only delete their OWN ticket, AND only until it is assigned (assigned_to is null and status is PENDING/OPEN)
 */
const deleteTicket = async (req, res, next) => {
  try {
    const ticketId = req.params.id;
    const ticket = await ticketsService.getTicketById(ticketId);

    if (!ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    // Role-based authorization & assignment validation for regular users
    if (req.user && req.user.role === "user") {
      const isOwner =
        String(ticket.user_id) === String(req.user.uid) ||
        (req.user.dbId && String(ticket.user_id) === String(req.user.dbId));

      if (!isOwner) {
        return res.status(403).json({
          success: false,
          message: "Forbidden: You do not have permission to delete another user's ticket.",
        });
      }

      if (ticket.assigned_to) {
        return res.status(403).json({
          success: false,
          message: "Cannot cancel or delete a ticket once it has been assigned.",
        });
      }

      const status = (ticket.status || "").toUpperCase();
      if (status !== "PENDING" && status !== "OPEN") {
        return res.status(403).json({
          success: false,
          message: "Cannot cancel a ticket that is already in progress or completed.",
        });
      }
    }

    const deletedTicket = await ticketsService.deleteTicket(ticketId);

    res.json({
      success: true,
      message: "Ticket deleted successfully",
      data: deletedTicket,
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createTicket,
  getTickets,
  getMyTickets,
  getAssignedTickets,
  getTicketsByEmail,
  getTicketsbyEmail: getTicketsByEmail,
  getTicketById,
  updateTicket,
  updateTicketStatus,
  assignTicket,
  deleteTicket,
};