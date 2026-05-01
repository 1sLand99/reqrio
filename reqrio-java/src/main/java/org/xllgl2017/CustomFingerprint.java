package org.xllgl2017;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class CustomFingerprint {
    List<Integer> suites = new ArrayList<>();
    List<Integer> groups = new ArrayList<>();
    List<Integer> algorithms = new ArrayList<>();
    List<Integer> versions = new ArrayList<>();
    List<Integer> ec_formats = new ArrayList<>();
    List<Integer> compression_methods = new ArrayList<>();
    List<Integer> extensions = new ArrayList<>();
    HashMap<String, JsonElement> settings = new HashMap<>();
    int window_size;
    int weight;
    boolean priority;


    public void addSuite(CipherSuite suite) {
        this.addSuite(suite.value);
    }

    public void addSuite(int suite) {
        this.suites.add(suite);
    }

    public void addGroup(SupportGroup group) {
        this.addGroup(group.value);
    }

    public void addGroup(int group) {
        this.groups.add(group);
    }

    public void addAlgorithm(Algorithm algorithm) {
        this.addAlgorithm(algorithm.value);
    }

    public void addAlgorithm(int algorithm) {
        this.algorithms.add(algorithm);
    }

    public void addVersion(Version version) {
        this.addVersion(version.value);
    }

    public void addVersion(int version) {
        this.versions.add(version);
    }

    public void addEcPointFormat(EcPointFormat format) {
        this.addEcPointFormat(format.value);
    }

    public void addEcPointFormat(int format) {
        this.ec_formats.add(format);
    }

    public void addCompressionMethod(CompressionMethod method) {
        this.addCompressionMethod(method.value);
    }

    public void addCompressionMethod(int method) {
        this.compression_methods.add(method);
    }

    public void addExtension(ExtensionType extensionType) {
        this.addExtension(extensionType.value);
    }

    public void addExtension(int value) {
        this.extensions.add(value);
    }

    public void addSetting(H2SettingType type, int value) {
        this.settings.put(type.value, new JsonPrimitive(value));
    }

    public void addSetting(int flag, int value) {
        JsonObject obj = new JsonObject();
        obj.add("flag", new JsonPrimitive(flag));
        obj.add("value", new JsonPrimitive(value));
        this.settings.put(H2SettingType.Reversed.value, obj);
    }

    public void setWindowSize(int size) {
        this.window_size = size;
    }

    public void setPriority(boolean priority, int weight) {
        this.priority = priority;
        this.weight = weight;
    }
}


