package org.xllgl2017;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Headers {
    private String uri;
    private Method method;
    private int status;
    private String agreement;
    private final HashMap<String, String> keys;
    private final List<Cookie> cookies;

    public Headers() {
        this.keys = new HashMap<>();
        this.cookies = new ArrayList<>();
    }

    public Headers(JsonObject header) {
        this.uri = header.get("uri").toString();
        Gson gson = new Gson();
        this.method = gson.fromJson(header.get("method").getAsString(), Method.class);
        this.status = header.get("status").getAsInt();
        this.agreement = header.get("agreement").toString();
        this.keys = new HashMap<>();
        this.cookies = new ArrayList<>();
        JsonObject ks = header.get("keys").getAsJsonObject();

        for (String k : ks.keySet()) {
            if (k.startsWith("HTTP/")) continue;
            if (k.equalsIgnoreCase("set-cookie")) {
                JsonArray cookies = ks.getAsJsonArray(k);
                for (JsonElement cookie : cookies) {
                    this.cookies.add(gson.fromJson(cookie, Cookie.class));
                }
            } else {
                this.keys.put(k, ks.get(k).getAsString());
            }
        }
    }

    public void addHeader(String name, String value) {
        this.keys.put(name, value);
    }

    public List<Cookie> getCookies() {
        return cookies;
    }

    public void addCookie(Cookie cookie) {
        this.cookies.add(cookie);
    }

    public void addCookie(String name, String value) {
        this.cookies.add(new Cookie(name, value));
    }

    public void setCookies(String cookies) {
        String[] items = cookies.split("; ");
        for (String item : items) {
            String[] kvs = item.split("=");
            if (kvs.length > 1) {
                this.addCookie(new Cookie(kvs[0], kvs[1]));
            } else {
                this.addCookie(new Cookie(kvs[0], ""));
            }
        }
    }

    public int getStatus() {
        return status;
    }

    public HashMap<String, String> getKeys() {
        return keys;
    }
}
