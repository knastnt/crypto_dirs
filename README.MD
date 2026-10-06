Получение конфигураций для сборки нативного приложения:

Несколько раз запусти приложение как обычный jar под трассирующим агентом. 
Прогони работу через весь необходимый функционал.
Он допишет в конфиги всё, что реально использовалось, включая JCA и JNI:

```bash
mvn clean package
/home/user/.jdks/graalvm-ce-21.0.2/bin/java -agentlib:native-image-agent=config-merge-dir=src/main/resources/META-INF/native-image/app/app -jar target/app-1.0.0-SNAPSHOT.jar
```
Далее можно собирать
нативное приложение с помощью GraalVM:

```bash
mvn -Pnative package
```