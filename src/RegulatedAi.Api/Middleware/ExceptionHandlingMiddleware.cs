using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Api.Middleware;

/// <summary>
/// Maps engine exceptions to HTTP responses.
/// </summary>
/// <remarks>
/// Centralised so that the mapping is stated once and cannot drift between controllers, and so
/// that the rule about what a client is told lives in one place. Clients get the category and, for
/// the cases they can act on, the reason; they never get a stack trace, and the details of an
/// output-contract violation stay server-side because they describe our internals and can name
/// documents the caller should not learn about.
/// </remarks>
public sealed class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (InvalidWorkflowRequestException exception)
        {
            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "Request rejected",
                exception.Message).ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException exception)
        {
            _logger.LogWarning(exception, "Rejected a request whose token claims were unusable.");

            await WriteProblemAsync(
                context,
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                exception.Message).ConfigureAwait(false);
        }
        catch (WorkflowContractViolationException exception)
        {
            // The violations are logged, not returned: they describe the engine's internals and
            // can name documents the caller has no business learning about.
            _logger.LogError(
                exception,
                "Withheld a workflow response that violated its output contract: {Violations}",
                string.Join(" | ", exception.Violations));

            await WriteProblemAsync(
                context,
                StatusCodes.Status500InternalServerError,
                "Response withheld",
                "The workflow produced a response that failed its own output checks, so it was not "
                + "returned. The incident has been audited.").ConfigureAwait(false);
        }
        catch (ArgumentException exception)
        {
            _logger.LogWarning(exception, "Rejected a malformed request.");

            await WriteProblemAsync(
                context,
                StatusCodes.Status400BadRequest,
                "Request rejected",
                exception.Message).ConfigureAwait(false);
        }
    }

    private static async Task WriteProblemAsync(
        HttpContext context,
        int statusCode,
        string title,
        string detail)
    {
        if (context.Response.HasStarted)
        {
            // Nothing safe to do at this point; the client already has a partial response.
            return;
        }

        var problem = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail,
            Instance = context.Request.Path,
        };

        problem.Extensions["correlationId"] = context.TraceIdentifier;

        context.Response.Clear();
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";

        await context.Response
            .WriteAsync(JsonSerializer.Serialize(problem, JsonOptions))
            .ConfigureAwait(false);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}
