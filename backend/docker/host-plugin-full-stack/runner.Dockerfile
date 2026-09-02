FROM mcr.microsoft.com/playwright:v1.62.0-noble

RUN groupmod --gid 10001 pwuser \
    && usermod --uid 10001 --gid 10001 pwuser \
    && install -d -o pwuser -g pwuser -m 0755 /work \
    && chown -R pwuser:pwuser /home/pwuser

WORKDIR /work

COPY --chown=pwuser:pwuser backend/test/e2e/host-plugin-full-stack/package.json backend/test/e2e/host-plugin-full-stack/package-lock.json ./
RUN npm ci --ignore-scripts
COPY --chown=pwuser:pwuser backend/test/e2e/host-plugin-full-stack/playwright.config.mjs backend/test/e2e/host-plugin-full-stack/acceptance.spec.mjs ./

USER pwuser
ENTRYPOINT ["npx", "playwright", "test", "--config", "playwright.config.mjs"]
