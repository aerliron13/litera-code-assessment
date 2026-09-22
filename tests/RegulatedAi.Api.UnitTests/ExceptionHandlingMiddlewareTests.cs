using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using RegulatedAi.Api.Middleware;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// Exception-to-HTTP mapping. Centralised so the rule about what a client is told is stated once,
/// which is also why it is worth testing directly.
/// </summary>
public sealed class ExceptionHandlingMiddlewareTests
{
    private static async Task<(int StatusCode, string Body)> InvokeAsync(Exception? thrown)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/workflow/run";
        context.Response.Body = new MemoryStream();

        RequestDelegate next = _ => thrown is null ? Task.CompletedTask : Task.FromException(thrown);

        var middleware = new ExceptionHandlingMiddleware(
            next, NullLogger<ExceptionHandlingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var body = await new StreamReader(context.Response.Body).ReadToEndAsync();

        return (context.Response.StatusCode, body);
    }

    [Fact]
    public async Task Passes_a_successful_request_through_untouched()
    {
        var (statusCode, body) = await InvokeAsync(null);

        Assert.Equal(StatusCodes.Status200OK, statusCode);
        Assert.Empty(body);
    }

    [Fact]
    public async Task Maps_a_rejected_request_to_400_and_explains_why()
    {
        var (statusCode, body) = await InvokeAsync(
            new InvalidWorkflowRequestException("A subjectId is required."));

        Assert.Equal(StatusCodes.Status400BadRequest, statusCode);

        // A caller can act on this one, so they get the reason.
        Assert.Contains("A subjectId is required.", body);
    }

    [Fact]
    public async Task Maps_unusable_token_claims_to_401()
    {
        var (statusCode, _) = await InvokeAsync(
            new UnauthorizedAccessException("The token carries no recognised tenant claim."));

        Assert.Equal(StatusCodes.Status401Unauthorized, statusCode);
    }

    [Fact]
    public async Task Maps_a_malformed_argument_to_400()
    {
        var (statusCode, _) = await InvokeAsync(new ArgumentException("A tenant id is required."));

        Assert.Equal(StatusCodes.Status400BadRequest, statusCode);
    }

    [Fact]
    public async Task Maps_an_output_contract_violation_to_500()
    {
        var (statusCode, _) = await InvokeAsync(new WorkflowContractViolationException(
            new[] { "citation 'policy-b-002' was not returned by tenant-scoped retrieval" }));

        Assert.Equal(StatusCodes.Status500InternalServerError, statusCode);
    }

    /// <summary>
    /// The violations describe the engine's internals and can name documents the caller has no
    /// business learning about — including, in the case this backstop exists for, another tenant's
    /// document id. They are logged, never returned.
    /// </summary>
    [Fact]
    public async Task Does_not_leak_the_violation_details_to_the_caller()
    {
        var (_, body) = await InvokeAsync(new WorkflowContractViolationException(
            new[] { "citation 'policy-b-002' was not returned by tenant-scoped retrieval" }));

        Assert.DoesNotContain("policy-b-002", body);
        Assert.DoesNotContain("tenant-scoped retrieval", body);

        // The caller gets a generic statement that the response was withheld and audited.
        Assert.Contains("Response withheld", body);
        Assert.Contains("audited", body);
    }

    [Fact]
    public async Task Returns_problem_details_with_a_correlation_id()
    {
        var (_, body) = await InvokeAsync(new InvalidWorkflowRequestException("nope"));

        var problem = JsonDocument.Parse(body).RootElement;

        Assert.True(problem.TryGetProperty("title", out _));
        Assert.True(problem.TryGetProperty("detail", out _));
        Assert.True(problem.TryGetProperty("status", out _));
        Assert.True(problem.TryGetProperty("correlationId", out _));
        Assert.Equal("/api/workflow/run", problem.GetProperty("instance").GetString());
    }

    [Fact]
    public async Task Sets_the_problem_json_content_type()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        var middleware = new ExceptionHandlingMiddleware(
            _ => Task.FromException(new InvalidWorkflowRequestException("nope")),
            NullLogger<ExceptionHandlingMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.Equal("application/problem+json", context.Response.ContentType);
    }

    [Fact]
    public async Task Lets_an_unexpected_exception_propagate()
    {
        // Deliberately not caught: swallowing an exception this middleware does not understand
        // would turn an unknown failure into a misleading response.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => InvokeAsync(new InvalidOperationException("something unforeseen")));
    }
}
