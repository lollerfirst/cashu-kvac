from cffi import FFI
import os

ffibuilder = FFI()

if not os.path.exists("src/merlin/extension"):
    os.makedirs("src/merlin/extension")

try:
    ffibuilder.cdef(
        """
            typedef struct merlin_strobe128_ {
                /* XXX endianness */
                union {
                    uint64_t state[25];
                    uint8_t state_bytes[200];
                };
                uint8_t pos;
                uint8_t pos_begin;
                uint8_t cur_flags;
            } merlin_strobe128;

            typedef struct merlin_transcript_ {
                merlin_strobe128 sctx;
            } merlin_transcript;

            void merlin_transcript_init(merlin_transcript* mctx,
                            const uint8_t* label,
                            size_t label_len);

            void merlin_transcript_commit_bytes(merlin_transcript* mctx,
                                    const uint8_t* label,
                                    size_t label_len,
                                    const uint8_t* data,
                                    size_t data_len);

            void merlin_transcript_challenge_bytes(merlin_transcript* mctx,
                                       const uint8_t* label,
                                       size_t label_len,
                                       uint8_t* buffer,
                                       size_t buffer_len);
        """
    )
    ffibuilder.set_source("src.merlin.extension._merlin", 
        """
            #include "../../../libmerlin/src/merlin.h"
        """,
        sources=["libmerlin/src/merlin.c"]
    )

    ffibuilder.compile(verbose=True)
except Exception as e:
    print(f"Error compiling extension module: {e}")