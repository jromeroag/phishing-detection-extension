# Notas de revisión de SonarQube

- `random.Random(42)` en `backend/train.py` fija el orden de las muestras y del entrenamiento para obtener resultados reproducibles. No se usa para criptografía, tokens ni contraseñas. Se conserva sin cambios.
- `MANIFEST_PATH` en `tools/configure_extension.py` se construye con la raíz fija del proyecto y los componentes literales `extension/manifest.json`. No incorpora entrada del usuario; el hallazgo de escritura en una ruta controlada externamente es un falso positivo. Se conserva sin cambios.
