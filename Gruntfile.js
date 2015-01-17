"use strict";

module.exports = function(grunt) {
    grunt.loadNpmTasks("grunt-contrib-jshint");
    grunt.loadNpmTasks("grunt-jscs");

    grunt.initConfig({
        jshint: {
            all: {
                src: ["Gruntfile.js", "index.js", "lib/**/*.js", "test/**/*.js"],
                options: {
                    jshintrc: true
                }
            }
        },
        jscs: {
            all: {
                src: ["Gruntfile.js", "index.js", "lib/**/*.js", "test/**/*.js"]
            }
        }
    });

    grunt.registerTask("check", ["jshint", "jscs"]);
    grunt.registerTask("default", ["check"]);
};
