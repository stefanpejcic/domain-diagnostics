# domain-diagnostics
Domain Diagnostics - OpenPanel plugin to check IP/domain information

![screenshot](https://i.postimg.cc/zJzJq826/slika.png)

Installation:
```bash
docker exec openpanel bash -c "pip install dnspython" && \
  cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/domain-diagnostics && \
  docker restart openpanel
```

Update:
```bash
rm -rf /etc/openpanel/modules/domain-diagnostics && \
  docker exec openpanel bash -c "pip install dnspython" && \
  cd /etc/openpanel/modules/ && git clone https://github.com/stefanpejcic/domain-diagnostics && \
  docker restart openpanel
```

---

Documentation: https://openpanel.com/docs/articles/dev-experience/custom-plugins#example
