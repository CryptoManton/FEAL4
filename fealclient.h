#include "feal4.h"
#include "feal_req.h" /* error numbers */

/* feal_new_key muss aufgerufen werden, um im Daemon einen neuen Schluessel
 * zu generieren
 */
extern int feal_new_key (void);
/* feal_encrypt verschluesselt den plaintext mit dem geheimen Schluessel
 * und gibt den Chiffretext zurueck.
 * Returnwert: Anzahl der *danach* noch erlaubten feal_encrypt-
 * Operationen, oder -1 (E_EXCEED), wenn die Anzahl schon ueberschritten
 * ist, oder -2 (E_NOKEY), wenn feal_new_key nicht aufgerufen wurde,
 * oder schon feal_check_sub aufgerufen wurde
 */
extern int feal_encrypt (ByteType *plaintext, ByteType *ciphertext);
/* feal_check_sub ueberprueft die Teilschluessel key_trial.
 * key_trial[4] bis key_trial[11] muessen 0 sein, da diese Teilschluessel
 * vom Daemonen nicht verwendet werden (wird im Rahmenprogramm gesetzt).
 * Die tatsaechlich verwendeten Teilschluessel werden in key zurueckgegeben,
 * der 64-Bit (8-Byte)-Schluessel, aus dem diese Teilschluessel entstanden,
 * wird in key_orig zurueckgegeben (es kann auch ein NULL-Zeiger uebergeben
 * werden, wenn dieser Schluessel nicht interessiert).
 * Returnwert: 1 Schluessel war richtig
 *             0 Schluessel war falsch
 *  E_NOKEY (-2) Es gibt keinen Schluessel
 */
extern int feal_check_sub (ByteType key_trial[12][2], ByteType key[12][2],
  ByteType *key_orig);
