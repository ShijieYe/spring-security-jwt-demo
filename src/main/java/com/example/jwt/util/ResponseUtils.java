package com.example.jwt.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

@Slf4j
public class ResponseUtils {

    private ResponseUtils() {
    }

    /**
     * 使用response输出JSON
     *
     * @param response
     * @param result
     */
    public static void outHttpJson(HttpServletResponse response, Object result) {

        PrintWriter out = null;
        try {
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json");
            response.setStatus(200);
            out = response.getWriter();
            out.println(new ObjectMapper().writeValueAsString(result));
        } catch (Exception e) {
            log.error(e + "输出JSON出错");
        } finally {
            if (out != null) {
                out.flush();
                out.close();
            }
        }
    }

    public static void outJson(ServletResponse response, Object result) {

        PrintWriter out = null;
        try {
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json");
            out = response.getWriter();
            out.println(new ObjectMapper().writeValueAsString(result));
        } catch (Exception e) {
            log.error(e + "输出JSON出错");
        } finally {
            if (out != null) {
                out.flush();
                out.close();
            }
        }
    }
}
