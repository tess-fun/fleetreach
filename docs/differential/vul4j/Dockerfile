# The JaCoCo agent and command line on top of vul4j:base (see build.sh).
FROM vul4j:base
RUN mkdir -p /opt/jacoco && cd /opt/jacoco \
    && curl -fsSLo agent.jar https://repo1.maven.org/maven2/org/jacoco/org.jacoco.agent/0.8.12/org.jacoco.agent-0.8.12-runtime.jar \
    && curl -fsSLo cli.jar https://repo1.maven.org/maven2/org/jacoco/org.jacoco.cli/0.8.12/org.jacoco.cli-0.8.12-nodeps.jar
