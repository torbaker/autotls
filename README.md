# AutoTLS: Automate TLS Certificate Acquisition

Provides a programmatic method for a Java application to ensure that it has
the proper certificates necessary to provide TLS coverage for itself.

Simple example:
```java
    Path                appConfigDir = ...;
    Collection<String>  hostNames    = ...;    
    CertificateManager  manager      = CertificateManager.newInstance( appConfigDir );
    
    manager.requireCoverageFor( hostNames );
```

This is extracted from a larger project. It is here in the hope that someone
else will find it useful as we do.

See the 'com.orbaker.autotls.example.Example' class for examples.

## To Do

- Much better Javadoc

- Only the full builder example works at present. Yet to be implemented are:
  
  - newPropertyInstance() in CertificateManager
  - newXMLInstance() in CertificateManager

- JMX integration to provide certificate information.

- CertificateMonitor that will send events when certificates are at or near
  expiration.

- There are no actions attached. If having binary releases is important to you,
  you are welcome to contribute a working YAML. I have wasted enough time on
  this task.

## Wish List

- Implement a standard DDNS-01 challenge so that wildcard certificates are
  possible. This might be impossible to do globally as there doesn't seem to
  be a global standard here.
