using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using RegulatedAi.Api.Auth;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Api.Cors;
using RegulatedAi.Api.Middleware;
using RegulatedAi.Core.Actions;
using RegulatedAi.Core.Actions.Handlers;
using RegulatedAi.Core.Approvals;
using RegulatedAi.Core.Audit;
using RegulatedAi.Core.Data;
using RegulatedAi.Core.Evidence;
using RegulatedAi.Core.Risk;
using RegulatedAi.Core.Security;
using RegulatedAi.Core.Workflow;

var builder = WebApplication.CreateBuilder(args);

// =============================================================================================
// Configuration
// =============================================================================================

builder.Services
    .AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    // Fail at startup, not at the first forged token.
    .Validate(options =>
    {
        options.Validate();
        return true;
    })
    .ValidateOnStart();

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
                 ?? throw new InvalidOperationException(
                     $"The '{JwtOptions.SectionName}' configuration section is missing.");
jwtOptions.Validate();

// Deny-by-default: an absent section means no browser origin is allowed, which is what ships.
var corsOptions = builder.Configuration.GetSection(CorsOptions.SectionName).Get<CorsOptions>()
                  ?? new CorsOptions();
corsOptions.Validate();

builder.Services
    .AddOptions<CorsOptions>()
    .Bind(builder.Configuration.GetSection(CorsOptions.SectionName))
    .Validate(options =>
    {
        options.Validate();
        return true;
    })
    .ValidateOnStart();

builder.Services.AddCors(options => options.AddPolicy(
    CorsOptions.PolicyName,
    policy => CorsConfiguration.Apply(policy, corsOptions)));

// =============================================================================================
// MVC and JSON
// =============================================================================================

// The JSON contract lives in RegulatedAiJsonOptions so a test can assert the published wire
// format. Note in particular that there is no global enum converter — see that file for why.
builder.Services
    .AddControllers()
    .AddJsonOptions(options => RegulatedAiJsonOptions.Configure(options.JsonSerializerOptions));

// =============================================================================================
// Data layer — in-memory, as the brief requires. See MemoryCacheStores.cs for the caveats.
// =============================================================================================

builder.Services.AddMemoryCache();

builder.Services.AddSingleton<IClock, SystemClock>();
builder.Services.AddSingleton<IEvidenceStore, MemoryCacheEvidenceStore>();
builder.Services.AddSingleton<IApprovalStore, MemoryCacheApprovalStore>();
builder.Services.AddSingleton<IAuditStore, MemoryCacheAuditStore>();
builder.Services.AddSingleton<IUserStore, MemoryCacheUserStore>();
builder.Services.AddSingleton<IDataSeeder, DataSeeder>();

// =============================================================================================
// Engine services
//
// Registered explicitly rather than behind an AddRegulatedAiCore() extension: the composition of
// this system is the part a reviewer most wants to see, so it is stated here in full.
// =============================================================================================

builder.Services.AddSingleton<ITokenService, JwtTokenService>();
builder.Services.AddSingleton<IPromptInjectionScanner, PromptInjectionScanner>();
builder.Services.AddSingleton<IEvidenceService, EvidenceService>();
builder.Services.AddSingleton<IRiskService, RiskService>();
builder.Services.AddSingleton<IAuditService, AuditService>();
builder.Services.AddSingleton<IApprovalService, ApprovalService>();
builder.Services.AddSingleton<IActionService, ActionService>();
builder.Services.AddSingleton<IWorkflowService, WorkflowService>();

// --- Action handlers -------------------------------------------------------------------------
// One registration per risky action. ActionService collects every IActionHandler and dispatches
// by name, so adding an action (for example exportPrivilegedSummary) is a new class plus a line
// here — with no change to the orchestrator, the approval gate or the audit trail.
builder.Services.AddSingleton<IActionHandler, MarkVendorApprovedHandler>();

// =============================================================================================
// Authentication and authorization
// =============================================================================================

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Both halves live in JwtBearerConfiguration so they can be unit-tested directly: a
        // tampered or re-signed token must be rejected, and that is too important a property to
        // infer from the presence of this call.
        options.TokenValidationParameters =
            JwtBearerConfiguration.CreateTokenValidationParameters(jwtOptions);

        // Replace the default handler with one whose claim-name mapping is configured explicitly,
        // so "sub" and "role" reach application code under the names the token actually carries.
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(JwtBearerConfiguration.CreateTokenHandler());

        options.Events = new JwtBearerEvents
        {
            // A correctly signed token is still not usable unless it names a tenant and a role we
            // recognise. Checking here means the rest of the pipeline can treat the presence of
            // those claims as an invariant rather than a possibility.
            OnTokenValidated = context =>
            {
                var failure = JwtBearerConfiguration.DescribeClaimFailure(context.Principal);

                if (failure is not null)
                {
                    context.Fail(failure);
                }

                return Task.CompletedTask;
            },
        };
    });

builder.Services.AddAuthorization();

// =============================================================================================
// Swagger
// =============================================================================================

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Regulated AI Action Workflow Engine",
        Version = "v1",
        Description =
            "Retrieves tenant-scoped evidence, evaluates risk, blocks high-risk actions until a "
            + "human approval is recorded, and audits every run and attempt.",
    });

    var scheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste the accessToken returned by POST /api/auth/login.",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme,
        },
    };

    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, scheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement { [scheme] = Array.Empty<string>() });
});

var app = builder.Build();

// =============================================================================================
// Seed the in-memory corpus before serving traffic
// =============================================================================================

using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<IDataSeeder>().Seed(jwtOptions.SeedUserPassword);
}

// =============================================================================================
// Pipeline
// =============================================================================================

// First, so it catches everything below it.
app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "Regulated AI Action Workflow Engine v1");
    options.DocumentTitle = "Regulated AI Action Workflow Engine";
});

// Before authentication, so a rejected preflight never reaches it. Preflight requests carry no
// credentials, and a 401 on an OPTIONS request reads to the browser as a CORS failure anyway.
app.UseCors(CorsOptions.PolicyName);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapGet("/", () => Results.Redirect("/swagger")).AllowAnonymous();

app.Run();

/// <summary>
/// Exposed so the integration tests can host the real application through
/// <c>WebApplicationFactory&lt;Program&gt;</c> — the tests exercise this pipeline, including
/// authentication, not a re-registered subset of it.
/// </summary>
public partial class Program
{
}
