cat > run.sh <<'EOF'
#!/bin/sh
PORT=${1:-53}
while true; do
    ./main "$PORT" >> resolver.log 2>&1
    sleep 1
done
EOF
chmod +x run.sh

printf 'main\n*.o\n*.dSYM/\nresolver.log\n' > .gitignore