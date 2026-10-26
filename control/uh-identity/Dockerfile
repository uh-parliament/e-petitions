FROM uhparliament/e-petitions:parliament-native-staff-auth-v3-20261026
WORKDIR /app
COPY public/uh-parliament-brand/ /app/public/uh-parliament-brand/
COPY app/views/admin/admin/index.html.erb /app/app/views/admin/admin/index.html.erb
COPY app/views/application/_footer.html.erb /app/app/views/application/_footer.html.erb
COPY app/views/layouts/editor.html.erb /app/app/views/layouts/editor.html.erb
COPY app/views/layouts/application.html.erb /app/app/views/layouts/application.html.erb
COPY app/views/layouts/admin.html.erb /app/app/views/layouts/admin.html.erb
RUN rm -f /app/app/assets/images/graphics/graphic_crest-large-white.png \
             /app/app/assets/images/graphics/graphic_crest-large-white-2x.png \
             /app/app/assets/images/graphics/graphic_crest-large-grey.png \
             /app/app/assets/images/graphics/graphic_crest-large-grey-2x.png \
             /app/app/assets/images/frontend/uk-government-logo.svg \
    && find /app/public/assets -type f \( -name 'graphic_crest-large-*.png' -o -name 'uk-government-logo-*.svg' \) -delete