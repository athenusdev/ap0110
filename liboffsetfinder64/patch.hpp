//
//  patch.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef patch_hpp
#define patch_hpp

#include <liboffsetfinder64/common.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

namespace tihmstar {
    namespace patchfinder64{
        
        class patch{
            bool _slideme;
            void(*_slidefunc)(class patch *patch, uintptr_t slide);
        public:
            loc_t _location;
            void *_patch;
            size_t _patchSize;
            patch(loc_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uintptr_t slide) = NULL);
            patch(const patch& cpy);
            patch(patch &&cpy);
            void slide(uintptr_t slide);
            patch &operator=(const patch &p);
            patch &operator=(patch &&p);
            patch();
            ~patch();
        };
        
    }
}

#endif /* patch_hpp */
