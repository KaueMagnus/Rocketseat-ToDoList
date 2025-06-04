package br.com.kauemagnus.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.kauemagnus.todolist.user.UserModel;
import br.com.kauemagnus.todolist.user.UserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private UserRepository userRepository; // Changed to IUserRepository based on common Spring Data JPA naming

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servletPath = request.getServletPath();

        if (servletPath.startsWith("/tasks/")) {
            // Pegar a autenticação (usuário e senha)
            var authorizationHeader = request.getHeader("Authorization"); // Renamed for clarity

            if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("basic ")) {
                // The header exists and starts with "Basic " (case-insensitive check for "basic")

                var authEncoded = authorizationHeader.substring("Basic ".length()).trim(); // Ensure space after "Basic"

                byte[] authDecoded;
                try {
                    authDecoded = Base64.getDecoder().decode(authEncoded);
                } catch (IllegalArgumentException e) {
                    // Handle cases where the Base64 string is invalid
                    System.err.println("Invalid Base64 encoding in Authorization header: " + e.getMessage());
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Authorization header encoding.");
                    return;
                }

                var authString = new String(authDecoded); // Default charset, consider specifying (e.g., StandardCharsets.UTF_8)

                String[] credentials = authString.split(":", 2); // Split into 2 parts max
                if (credentials.length == 2) {
                    String username = credentials[0];
                    String password = credentials[1];

                    // System.out.println("Authorization");
                    // System.out.println("Username: " + username);
                    // System.out.println("Password: " + (password != null ? "[PRESENT]" : "[NOT PRESENT]")); // Avoid logging password directly

                    // Validar usuário
                    UserModel user = this.userRepository.findByUsername(username); // Assuming findByUsername returns UserModel
                    if (user == null) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found.");
                    } else {
                        // Validar senha
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                        if (passwordVerify.verified) {
                            request.setAttribute("idUser", user.getId());
                            filterChain.doFilter(request, response);
                        } else {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid username or password.");
                        }
                    }
                } else {
                    // Credentials format is incorrect (not "username:password")
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Authorization header format.");
                }
            } else {
                // Authorization header is missing or doesn't start with "Basic "
                System.err.println("Authorization header is missing or not Basic type.");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization header required.");
                // No need to return here explicitly as the filter chain won't be called
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}