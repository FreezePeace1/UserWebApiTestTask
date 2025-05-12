using Serilog;
using UserWebApi;
using UserWebApi.Application.DependencyInjection;
using UserWebApi.Application.Services.Data;
using UserWebApi.DAL.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddSwagger();
builder.Services.AddHttpContextAccessor();
builder.Services.AddDAL(builder.Configuration);
builder.Services.AddJwt(builder);
builder.Host.UseSerilog((context, configuration) => configuration.ReadFrom.Configuration(context.Configuration));
builder.Services.AddServices();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => {
        c.RoutePrefix = string.Empty;
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "User.Api v1");
    });
}

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var initializer = scope.ServiceProvider.GetRequiredService<Initializer>();
    initializer.Initialize();
}

app.MapControllers();

app.Run();
