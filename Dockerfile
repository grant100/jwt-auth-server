FROM openjdk:8-jdk-alpine
ENV APP_HOME /apps/poc
RUN mkdir -p $APP_HOME

WORKDIR $APP_HOME
#COPY build/resources/*.properties $APP_HOME
#COPY build/resources/*.yaml $APP_HOME
COPY build/resources/ $APP_HOME
COPY build/libs/*.jar $APP_HOME
RUN ln -s poc-authentication-server-*.jar poc-auth.jar
RUN ls -a
ENTRYPOINT ["java", "-jar", "-Dspring.config.location=apps/poc/application.properties,/apps/poc/application.yaml", "poc-auth.jar"]
