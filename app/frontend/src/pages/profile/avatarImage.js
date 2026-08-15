// Prépare la photo de profil côté navigateur : recadrage carré centré + réduction à 256 px,
// pour n'envoyer au serveur qu'un data URI léger (~20-40 Ko) quelle que soit la taille d'origine.
export const AVATAR_SIZE = 256;
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

export function fileToAvatarDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Lecture du fichier impossible."));
    reader.onload = () => {
      const image = new Image();
      image.onerror = () => reject(new Error("Ce fichier n'est pas une image valide."));
      image.onload = () => {
        // Recadrage carré centré : on garde le plus grand carré possible au centre de l'image.
        const side = Math.min(image.width, image.height);
        const offsetX = (image.width - side) / 2;
        const offsetY = (image.height - side) / 2;

        const canvas = document.createElement("canvas");
        canvas.width = AVATAR_SIZE;
        canvas.height = AVATAR_SIZE;
        const context = canvas.getContext("2d");
        context.drawImage(image, offsetX, offsetY, side, side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);

        resolve(canvas.toDataURL("image/jpeg", 0.85));
      };
      image.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}
