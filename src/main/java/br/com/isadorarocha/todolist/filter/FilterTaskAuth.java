package br.com.isadorarocha.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.isadorarocha.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                @Autowired
                private IUserRepository userRepository;

                //Pegar autenticação (usuario e senha)
                var authorization = request.getHeader("Authorization");
                
                var authEncoded = authorization.substring("Basic".length()).trim(); // remover o Basic
                
                byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

                var authString = new String(authDecoded);

                // ["isadorarocha", "12345"]
                String[] credentials = authString.split(":");
                String username = credentials[0];
                String password = credentials[1];
                //System.out.println("authorization");
                //System.out.println(username);
                //System.out.println(password);

                //Validar usuário
                var user = this.userRepository.findByUsername(username);
                if(user == null) {
                    response.sendError(401);
                } else {
                    //Validar senha 
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified) {
                        filterChain.doFilter(request, response);
                    } else {
                        response.sendError(401);
                    }
                    
                    //Seguir viagem

                    filterChain.doFilter(request, response);
                }
            
    }

  
    
}
