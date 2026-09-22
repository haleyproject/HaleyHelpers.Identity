namespace Haley.Models;

public sealed record ConfirmTotpTicketRequest(string Ticket, string Code);
