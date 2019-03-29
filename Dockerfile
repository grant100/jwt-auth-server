FROM openjdk:8-jdk-alpine
ENV APP_HOME /apps/poc
RUN mkdir -p $APP_HOME

WORKDIR $APP_HOME
COPY build/resources/main $APP_HOME
COPY build/libs/*.jar $APP_HOME
RUN ln -s poc-authentication-server-*.jar poc-auth.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "-Dspring.config.location=application.properties,application.yaml", "poc-auth.jar"]
