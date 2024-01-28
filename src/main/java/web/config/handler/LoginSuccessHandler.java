package web.config.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

//@Component
//public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
//
////    @Override
////    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
////                                        HttpServletResponse httpServletResponse,
////                                        Authentication authentication) throws IOException, ServletException {
////        httpServletResponse.sendRedirect("/hello");
////    }
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        handle(request, response, authentication);
//        clearAuthenticationAttributes(request);
//    }
//
//    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
//        String targetUrl = determineTargetUrl(authentication);
//
//        if (response.isCommitted()) {
//            // Логирование ошибок
//            return;
//        }
//
//        response.sendRedirect(targetUrl);
//    }
//
//    protected String determineTargetUrl(Authentication authentication) {
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        for (GrantedAuthority authority : authorities) {
//            if (authority.getAuthority().equals("admin")) {
//                return "/admin";
//            } else if (authority.getAuthority().equals("user")) {
//                return "/user";
//            }
//        }
//        // Если не удалось определить URL для роли пользователя, предположим, что это общая главная страница
//        return "/hello";
//    }
//}

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {
        // В зависимости от роли пользователя, перенаправляем на соответствующую страницу
        if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            httpServletResponse.sendRedirect("/admin");
        } else {
            httpServletResponse.sendRedirect("/user");
        }
    }
}