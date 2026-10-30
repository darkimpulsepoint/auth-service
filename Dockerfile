# STAGE 1 Build jar
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw && ./mvnw -B dependency:go-offline

COPY src src
RUN ./mvnw -B -DskipTests package

# STAGE 2
FROM eclipse-temurin:25-jre
WORKDIR /app

RUN useradd --system --no-create-home appuser
USER appuser

COPY --from=build /workspace/target/*.jar app.jar

EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
