#先把springboot项目打成jar包: gradle bootJar(gradle:build:bootJar)
#gradle bootJar
docker build -t peacerise-auth:v0.0.1 .
docker run -p 9000:9000 -d peacerise-auth:v0.0.1