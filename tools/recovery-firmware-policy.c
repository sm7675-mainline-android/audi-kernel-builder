#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/kernel_to_cil.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>

static int allow_firmware(policydb_t *policy)
{
    class_datum_t *system_class = hashtab_search(policy->p_classes.table, "system");
    type_datum_t *kernel_type = hashtab_search(policy->p_types.table, "kernel");
    const char *targets[] = {"rootfs", "vendor_file"};
    if (!system_class || !kernel_type || system_class->comdatum)
        return -1;
    perm_datum_t *permission = hashtab_search(system_class->permissions.table, "firmware_load");
    if (!permission) {
        if (system_class->permissions.nprim >= 32)
            return -1;
        permission = calloc(1, sizeof(*permission));
        char *name = strdup("firmware_load");
        if (!permission || !name) {
            free(permission);
            free(name);
            return -1;
        }
        permission->s.value = system_class->permissions.nprim + 1;
        if (hashtab_insert(system_class->permissions.table, name, permission)) {
            free(permission);
            free(name);
            return -1;
        }
        system_class->permissions.nprim++;
    }
    if (!permission->s.value || permission->s.value > 32)
        return -1;
    uint32_t permission_mask = UINT32_C(1) << (permission->s.value - 1);
    for (size_t index = 0; index < sizeof(targets) / sizeof(targets[0]); index++) {
        type_datum_t *target = hashtab_search(policy->p_types.table, targets[index]);
        if (!target)
            return -1;
        avtab_key_t key = {
            .source_type = kernel_type->s.value,
            .target_type = target->s.value,
            .target_class = system_class->s.value,
            .specified = AVTAB_ALLOWED,
        };
        avtab_datum_t *existing = avtab_search(&policy->te_avtab, &key);
        if (existing) {
            existing->data |= permission_mask;
        } else {
            avtab_datum_t datum = {.data = permission_mask};
            if (avtab_insert(&policy->te_avtab, &key, &datum))
                return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s INPUT OUTPUT | --cil INPUT\n", argv[0]);
        return 2;
    }
    int dump = strcmp(argv[1], "--cil") == 0;
    FILE *input = fopen(argv[dump ? 2 : 1], "rb");
    if (!input) {
        perror("open input policy");
        return 1;
    }
    policydb_t policy;
    if (policydb_init(&policy)) {
        fclose(input);
        return 1;
    }
    struct policy_file policy_file;
    policy_file_init(&policy_file);
    policy_file.type = PF_USE_STDIO;
    policy_file.fp = input;
    int result = policydb_read(&policy, &policy_file, 0);
    fclose(input);
    if (result) {
        fprintf(stderr, "cannot read input policy\n");
        policydb_destroy(&policy);
        return 1;
    }
    if (dump) {
        result = sepol_kernel_policydb_to_cil(stdout, &policy);
    } else if (allow_firmware(&policy)) {
        fprintf(stderr, "cannot add recovery firmware permission\n");
        result = -1;
    } else {
        FILE *output = fopen(argv[2], "wb");
        if (!output) {
            perror("open output policy");
            result = -1;
        } else {
            policy_file.fp = output;
            result = policydb_write(&policy, &policy_file);
            if (fclose(output))
                result = -1;
        }
    }
    policydb_destroy(&policy);
    return result ? 1 : 0;
}
