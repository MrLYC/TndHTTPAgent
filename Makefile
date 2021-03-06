CONFDIR := ./conf

.PHONY: supervisor
supervisor:
	apt-get install supervisor

.PHONY: deploy
deploy:
	cp $(CONFDIR)/http_agent.supervisor.conf /etc/supervisor/conf.d/http_agent.supervisor.conf
	sed -i 's:%(ENV_TND_HTTP_AGENT_PATH)s:'`pwd`':g' /etc/supervisor/conf.d/http_agent.supervisor.conf
	supervisorctl reload all

	cp $(CONFDIR)/http_agent.nginx.site /usr/local/nginx/conf/sites/
	service nginx reload

.PHONY: feature-test
feature-test:
	./tests/http_agent_feature_test_driver.sh
