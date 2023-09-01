## JitPack

- https://jitpack.io/#toranova/kamelet-beans

## References

- https://camel.apache.org/manual/property-binding.html
- https://camel.apache.org/camel-k/2.0.x/configuration/dependencies.html
- https://camel.apache.org/camel-k/2.0.x/installation/advanced/maven.html
- https://jitpack.io/#toranova/kamelet-beans/master-SNAPSHOT
- https://github.com/apache/camel-kamelets/tree/main/kamelets
- https://camel.apache.org/components/4.0.x/eips/unmarshal-eip.html

## Troubleshooting

1. cannot create bean - please ensure that the camel-k version is correct (check pom.xml), or that the constructor can run. reasons for why the constructor may fail:

- invalid aws key / key-id combo
- cannot reach aws (proxy error)
