const express = require("express");
const router = express.Router();
const ticketsController = require("./tickets.controller");
const ticketRepliesController = require("../ticket_replies/ticket_replies.controller");
const ticketFeedbackController = require("../ticket_feedback/ticket_feedback.controller");
const authenticate = require("../../middleware/authenticate");
const authorize = require("../../middleware/authorize");

// Dedicated endpoints (must be defined before /:id)
router.get("/my", authenticate, authorize("user", "agent", "admin"), ticketsController.getMyTickets);
router.get("/assigned", authenticate, authorize("agent", "admin"), ticketsController.getAssignedTickets);

// Base ticket routes: /api/tickets
router.post("/", authenticate, authorize("user", "agent", "admin"), ticketsController.createTicket);
router.get("/", authenticate, authorize("user", "agent", "admin"), ticketsController.getTickets);
router.get("/:id", authenticate, authorize("user", "agent", "admin"), ticketsController.getTicketById);

// Replies nested routes
router.post("/:id/replies", authenticate, authorize("user", "agent", "admin"), ticketRepliesController.createReply);
router.get("/:id/replies", authenticate, authorize("user", "agent", "admin"), ticketRepliesController.getRepliesByTicket);

// Feedback nested routes
router.post("/:id/feedback", authenticate, authorize("user", "agent", "admin"), ticketFeedbackController.createFeedback);
router.get("/:id/feedback", authenticate, authorize("user", "agent", "admin"), ticketFeedbackController.getFeedbackByTicket);
router.patch("/:id/feedback", authenticate, authorize("user", "agent", "admin"), ticketFeedbackController.updateFeedback);
router.delete("/:id/feedback", authenticate, authorize("admin"), ticketFeedbackController.deleteFeedback);

// Specific action routes
router.patch("/:id/status", authenticate, authorize("agent", "admin"), ticketsController.updateTicketStatus);
router.patch("/:id/assign", authenticate, authorize("agent", "admin"), ticketsController.assignTicket);
router.patch("/:id", authenticate, authorize("agent", "admin"), ticketsController.updateTicket);
router.delete("/:id", authenticate, authorize("user", "agent", "admin"), ticketsController.deleteTicket);

module.exports = router;