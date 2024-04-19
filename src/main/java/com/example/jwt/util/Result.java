package com.example.jwt.util;

import lombok.*;
import lombok.experimental.Accessors;
import org.springframework.http.HttpStatus;

import java.io.Serial;
import java.io.Serializable;

@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
public class Result<T> implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Setter
    private String msg;

    @Setter
    private int code = HttpStatus.OK.value();

    @Setter
    private T data;

    public static <T> Result<T> success() {
        return restResult(null, HttpStatus.OK.value(), null);
    }


    public static <T> Result<T> success(T data) {
        return restResult(data, HttpStatus.OK.value(), null);
    }

    public static <T> Result<T> success(T data, String msg) {
        return restResult(data, HttpStatus.OK.value(), msg);
    }

    public static <T> Result<T> successMsg(String msg) {
        return restResult(null, HttpStatus.OK.value(), msg);
    }

    public static <T> Result<T> isSuccess(boolean flag) {
        return flag ? success() : failed();
    }

    public static <T> Result<T> failed() {
        return restResult(null, HttpStatus.INTERNAL_SERVER_ERROR.value(), null);
    }


    public static <T> Result<T> failed(int code, String msg) {
        return restResult(null, code, msg);
    }

    public static <T> Result<T> failed(String msg) {
        return restResult(null, HttpStatus.INTERNAL_SERVER_ERROR.value(), msg);
    }

    public static <T> Result<T> failed(String msg, T data) {
        return restResult(data, HttpStatus.INTERNAL_SERVER_ERROR.value(), msg);
    }


    public static <T> Result<T> restResult(T data, int code, String msg) {
        Result<T> apiResult = new Result<>();
        apiResult.setCode(code);
        apiResult.setData(data);
        apiResult.setMsg(msg);
        return apiResult;
    }
}
