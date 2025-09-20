# domain-diagnostics
Domain Diagnostics - OpenPanel plugin to check IP/domain information



Installation:
```bash
cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/domain-diagnostics && \
  docker restart openpanel
```

Update:
```bash
rm -rf /etc/openpanel/modules/domain-diagnostics && \
  cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/domain-diagnostics && \
  docker restart openpanel
```

---

Documentation: https://openpanel.com/docs/articles/dev-experience/custom-plugins#example
