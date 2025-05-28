package br.com.kauemagnus.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.kauemagnus.todolist.user.UserRepository;
import com.fasterxml.jackson.databind.ser.Serializers;
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
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
             throws ServletException, IOException {

                var servletPath = request.getServletPath();

                if(servletPath.equals("/tasks/")) {
                    // Pegar a autenticação (usuário e senha)
                    var authorization = request.getHeader("Authorization");


                    var authEnconded = authorization.substring("Basic".length()).trim();

                    byte[] authDecoded = Base64.getDecoder().decode(authEnconded);

                    var authString = new String(authDecoded);

                    String[] credentials = authString.split(":");
                    String username = credentials[0];
                    String password = credentials[1];

                    System.out.println("Authorization");
                    System.out.println(username);
                    System.out.println(password);

                    // Validar usuário
                    var user = this.userRepository.findByUsername(username);
                    if (user == null) {
                        response.sendError(401);
                    } else {
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                        if(passwordVerify.verified) {
                            request.setAttribute("idUser", user.getId());
                            filterChain.doFilter(request, response);
                        } else {
                            response.sendError(401);
                        }
                    }
                    // Validar senha

                } else {
                    filterChain.doFilter(request, response);
                }
    }
}
